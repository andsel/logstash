# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require "digest"
require "set"

module LogStash
  class SslFileTracker
    include LogStash::Util::Loggable

    # Known SSL file-path config names that may be declared with a non-path. Some plugins (beats) use :array as validate type
    PLUGIN_SSL_PATH_CONFIG_NAMES = %w[
      ssl_certificate
      ssl_key
      ssl_certificate_authorities
      ssl_keystore_path
      ssl_truststore_path
    ].freeze

    # Holds all per-path watch state in one place.
    # stamp:    latest change stamp. SHA-256 string for :watch paths; mtime (Time) for :poll paths.
    # callback: the FileChangeCallback registered with FileWatchService. nil for polled paths.
    # pipeline_ids:     Set of pipeline_ids referencing this path. The Java watch is removed only when pipeline_ids is empty.
    # mode:     :watch for regular files (WatchService-driven), :poll for symlinks (mtime on each converge).
    WatchedFile = Struct.new(:stamp, :callback, :pipeline_ids, :mode) do
      def poll?
        mode == :poll
      end
    end

    def initialize(file_watch_service = nil)
      @file_watch_service = file_watch_service
      # set at registration time, { pipeline_id => { file_path => baseline_stamp } }
      @registered_stamps = {}
      # one entry per path, shared across pipelines, { file_path => WatchedFile(:stamp, :callback, :pipeline_ids, :mode) }
      @watched_files = {}
      @pipeline_ids = Set.new
      # pipeline IDs whose current cert stamp differs from their registration baseline;
      # persists until register_paths resets the baseline, so reload failures are retried
      @stale_pipeline_ids = Set.new
      @mutex = Mutex.new
    end

    # Registers an id (pipeline or xpack service) with explicit paths
    # @param id [Symbol, String]
    # @param paths [Array<String>]
    # @return [void]
    def register_paths(id, paths)
      id = id.to_sym
      # Compute stamps { file_path => stamp } before taking the lock (filesystem I/O outside mutex).
      # Symlink paths use mtime; regular files use SHA-256.
      stamps = paths.each_with_object({}) do |p, h|
        h[p] = ::File.symlink?(p) ? compute_mtime(p) : compute_checksum(p)
      end
      new_registrations = {}

      @mutex.synchronize do
        baseline = {}
        paths.each do |path|
          entry = @watched_files[path]
          if entry.nil?
            if ::File.symlink?(path)
              entry = WatchedFile.new(stamps[path], nil, Set.new, :poll)
            else
              entry = WatchedFile.new(stamps[path], nil, Set.new, :watch)
              cb = build_callback(path)
              entry.callback = cb
              new_registrations[path] = cb
            end
            @watched_files[path] = entry
            logger.info("Registered path", :id => id, :path => path, :type => entry.poll? ? "symlink" : "file")
          end
          entry.pipeline_ids.add(id)
          baseline[path] = entry.stamp
        end
        @registered_stamps[id] = baseline
        @stale_pipeline_ids.delete(id)
      end

      new_registrations.each do |path, cb|
        @file_watch_service&.register(java.nio.file.Paths.get(path), cb)
      end
    end

    # Starts watching all SSL file paths for the pipeline. Paths already watched
    # by another pipeline share the same WatchedFile entry and are not re-registered.
    #
    # register() is called before pipeline startup so that any cert rotation
    # occurring during startup is detected and triggers a reload.
    # The worst case is one redundant reload.
    #
    # @param pipeline [JavaPipeline]
    # @return [void]
    def register(pipeline)
      pid = pipeline.pipeline_id.to_sym
      register_paths(pid, ssl_file_paths(pipeline))
      @mutex.synchronize { @pipeline_ids.add(pid) }
    end

    # Stops watching SSL file paths for the pipeline. Cancels the WatchKey only
    # when no other pipeline still references the path.
    # @param pipeline_id [Symbol, String]
    # @return [void]
    def deregister(pipeline_id)
      pid = pipeline_id.to_sym
      deregistrations = []

      @mutex.synchronize do
        @pipeline_ids.delete(pid)
        @stale_pipeline_ids.delete(pid)
        baseline = @registered_stamps.delete(pid)
        return unless baseline

        baseline.each_key do |path|
          entry = @watched_files[path]
          next unless entry

          entry.pipeline_ids.delete(pid)
          next unless entry.pipeline_ids.empty?

          @watched_files.delete(path)
          logger.info("Deregistered path", :pipeline_id => pid, :path => path)
          deregistrations << [path, entry.callback] unless entry.poll?
        end
      end

      deregistrations.each do |path, cb|
        @file_watch_service&.deregister(java.nio.file.Paths.get(path), cb)
      end
    end

    # Refreshes mtime stamps for :poll symlink paths belonging to the given ids,
    # then returns all IDs (from among the given ids) that are currently stale.
    # Stale set is accumulated by both poll refreshes and :watch file callbacks.
    # @param ids [Array, Set]
    # @return [Array<Symbol>] stale IDs from the given set
    def refresh_symlink_stamps(ids)
      return [] if ids.empty?
      id_filter = Set.new(Array(ids).map(&:to_sym))

      # Collect unique poll paths via registered_stamps (targeted lookup)
      polled_paths = @mutex.synchronize do
        id_filter.flat_map { |id| (@registered_stamps[id] || {}).keys }
                 .select { |p| @watched_files[p]&.poll? }
                 .uniq
      end

      # Stat outside mutex
      new_stamps = polled_paths.to_h { |p| [p, compute_mtime(p)] }.compact

      @mutex.synchronize do
        new_stamps.each do |(path, new_stamp)|
          entry = @watched_files[path]
          next if entry.nil? || entry.stamp == new_stamp
          logger.info("Symlink stamp changed", :path => path, :old_stamp => entry.stamp, :new_stamp => new_stamp)
          entry.stamp = new_stamp
          (entry.pipeline_ids & id_filter).each do |pid|
            baseline = @registered_stamps[pid]
            @stale_pipeline_ids.add(pid) if baseline && baseline[path] != entry.stamp
          end
        end
        (@stale_pipeline_ids & id_filter).to_a
      end
    end

    # Refreshes :poll symlink stamps for all registered pipelines and returns pipeline IDs
    # whose tracked cert files have changed since registration.
    # Handles both :poll paths (symlinks, statted on each call) and :watch paths
    # (regular files updated asynchronously by FileWatchService callbacks).
    # @return [Array<Symbol>] pipeline IDs that need reloading
    def refresh_pipeline_symlink_stamps
      ids = @mutex.synchronize { @pipeline_ids.dup }
      return [] if ids.empty?

      refresh_symlink_stamps(ids)
    end

    private

    # Returns a FileChangeCallback lambda that recomputes the SHA-256 checksum of path
    # and updates the stamp when it differs, marking affected pipelines stale.
    def build_callback(path)
      ->(event) {
        new_checksum = compute_checksum(path)
        @mutex.synchronize do
          entry = @watched_files[path]
          if entry && entry.stamp != new_checksum
            logger.info("Certificate changed", :path => path, :old_stamp => entry.stamp, :new_stamp => new_checksum)
            entry.stamp = new_checksum
            entry.pipeline_ids.each do |pid|
              baseline = @registered_stamps[pid]
              @stale_pipeline_ids.add(pid) if baseline && baseline[path] != entry.stamp
            end
          end
        end
      }
    end

    def compute_checksum(path)
      ::Digest::SHA256.file(path).hexdigest
    rescue SystemCallError, IOError
      nil
    end

    def compute_mtime(path)
      ::File.stat(path).mtime
    rescue SystemCallError, IOError
      nil
    end

    # Returns unique SSL file paths declared across all plugins in the pipeline
    # Scans each plugin's configs where the config name matches prefix "ssl_" and is a :path type,
    # or matches the exact name in PLUGIN_SSL_PATH_CONFIG_NAMES
    # @param pipeline [JavaPipeline]
    # @return [Array<String>]
    def ssl_file_paths(pipeline)
      (pipeline.inputs + pipeline.filters + pipeline.outputs).flat_map do |plugin|
        target = plugin.respond_to?(:ruby_plugin) ? plugin.ruby_plugin : plugin
        next [] if target.nil?

        target.class.get_config.to_a
              .select { |name, opts| PLUGIN_SSL_PATH_CONFIG_NAMES.include?(name.to_s) || (opts[:validate] == :path && name.to_s.start_with?("ssl_")) }
              .flat_map { |name, _| Array(target.instance_variable_get("@#{name}")) } # flat_map and Array() are for config that returns an array of certs
      end.uniq
    end
  end
end
