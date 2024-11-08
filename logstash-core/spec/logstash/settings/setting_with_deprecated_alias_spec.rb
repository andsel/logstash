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

require "spec_helper"
require "logstash/settings"
java_import org.apache.logging.log4j.core.appender.AbstractAppender

describe LogStash::Setting::SettingWithDeprecatedAlias do
  let(:canonical_setting_name) { "canonical.setting" }
  let(:deprecated_setting_name) { "legacy.setting" }

  let(:default_value) { "DeFaUlT" }

  let(:settings) { LogStash::Settings.new }
  let(:canonical_setting) { LogStash::Setting::StringSetting.new(canonical_setting_name, default_value, true) }

  class CustomAppender < AbstractAppender

    attr_reader :events_collector

    def initialize(events)
      super("CustomCaptorAppender", nil, nil, true, org.apache.logging.log4j.core.config.Property::EMPTY_ARRAY)
      @events_collector = events
    end

    # override the append to catch all the calls and collect the events
    def append(log_event)
      puts "DNADBG>> CustomAppender.append invoked log_event: #{log_event}"
      @events_collector << "#{log_event.message.formatted_message}"
      puts "DNADBG>> CustomAppender.append invoked list content: #{events_collector}"
    end
  end

  let(:events) { [] }

  before(:each) do
    # Initialization of appender and logger use to spy, need to be freshly recreated on each test is context shutdown is used.
    java_import org.apache.logging.log4j.LogManager
    logger = LogManager.getLogger("org.logstash.settings.DeprecatedAlias")
    java_import org.apache.logging.log4j.Level
    logger.setLevel(Level::INFO)
    expect(logger.info_enabled?).to be_truthy
    custom_appender = CustomAppender.new([])
    custom_appender.start
    logger.addAppender(custom_appender)
    #Verify the appender receives the log line from Logger
    custom_appender.events_collector << "12345"
    puts "DNADBG>> before - before calling log.info, events: #{custom_appender.events_collector}"
    logger.info("Test ping message")
    puts "DNADBG>> before - just after called log.info, events: #{custom_appender.events_collector}"

    expect(custom_appender.events_collector).not_to be_empty

    # expect(events[0].message.formatted_message).to include("Test ping message")
    events.clear

    allow(LogStash::Settings).to receive(:logger).and_return(double("SettingsLogger").as_null_object)
    allow(LogStash::Settings).to receive(:deprecation_logger).and_return(double("SettingsDeprecationLogger").as_null_object)

    settings.register(canonical_setting.with_deprecated_alias(deprecated_setting_name))
  end

  after(:each) do
    events.clear
  end

  # shared_examples '#validate_value success' do
  #   context '#validate_value' do
  #     it "returns without raising" do
  #       expect { settings.get_setting(canonical_setting_name).validate_value }.to_not raise_error
  #     end
  #   end
  # end
  #
  # xcontext "when neither canonical setting nor deprecated alias are set" do
  #   it 'resolves to the default' do
  #     expect(settings.get(canonical_setting_name)).to eq(default_value)
  #   end
  #
  #   it 'does not produce a relevant deprecation warning' do
  #     expect(LogStash::Settings.deprecation_logger).to_not have_received(:deprecated).with(a_string_including(deprecated_setting_name))
  #   end
  #
  #   include_examples '#validate_value success'
  #
  #   context "#observe_post_process" do
  #     it 'does not emit a deprecation warning' do
  #       expect(LogStash::Settings.deprecation_logger).to_not receive(:deprecated).with(a_string_including(deprecated_setting_name))
  #       settings.get_setting(deprecated_setting_name).observe_post_process
  #       expect(events).to be_empty
  #     end
  #   end
  # end

  # xcontext "when only the deprecated alias is set" do
  #   let(:value) { "crusty_value" }
  #
  #   before(:each) do
  #     settings.set(deprecated_setting_name, value)
  #     settings.get_setting(deprecated_setting_name).observe_post_process
  #   end
  #
  #   it 'resolves to the value provided for the deprecated alias' do
  #     expect(settings.get(canonical_setting_name)).to eq(value)
  #   end
  #
  #   it 'logs a deprecation warning' do
  #     expect(events[0].message.formatted_message).to include(deprecated_setting_name)
  #   end
  #
  #   include_examples '#validate_value success'
  #
  #   context "#observe_post_process" do
  #     it 're-emits the deprecation warning' do
  #       settings.get_setting(deprecated_setting_name).observe_post_process
  #       expect(events[0].message.formatted_message).to include(deprecated_setting_name)
  #     end
  #   end
  #
  #   it 'validates deprecated alias' do
  #     expect { settings.get_setting(canonical_setting_name).deprecated_alias.validate_value }.to_not raise_error
  #   end
  #
  #   context 'using a boolean setting' do
  #     let(:value) { true }
  #     let(:default_value) { false }
  #
  #     let(:canonical_setting) { LogStash::Setting::Boolean.new(canonical_setting_name, default_value, true) }
  #
  #     it 'resolves to the value provided for the deprecated alias' do
  #       expect(settings.get(canonical_setting_name)).to eq(true)
  #     end
  #
  #     include_examples '#validate_value success'
  #
  #     it 'validates deprecated alias' do
  #       expect { settings.get_setting(canonical_setting_name).deprecated_alias.validate_value }.to_not raise_error
  #     end
  #   end
  # end

  # xcontext "when only the canonical setting is set" do
  #   before(:each) do
  #     settings.set(canonical_setting_name, "shiny_value")
  #   end
  #
  #   it "resolves to the value provided for the canonical setting" do
  #     expect(settings.get(canonical_setting_name)).to eq("shiny_value")
  #   end
  #
  #   it 'does not produce a relevant deprecation warning' do
  #     settings.get_setting(deprecated_setting_name).observe_post_process
  #     expect(events).to be_empty
  #   end
  #
  #   include_examples '#validate_value success'
  #
  #   context "#observe_post_process" do
  #     it 'does not emit a deprecation warning' do
  #       settings.get_setting(deprecated_setting_name).observe_post_process
  #       expect(events).to be_empty
  #     end
  #   end
  # end

  # xcontext "when both the canonical setting and deprecated alias are set" do
  #   before(:each) do
  #     settings.set(deprecated_setting_name, "crusty_value")
  #     settings.set(canonical_setting_name, "shiny_value")
  #   end
  #
  #   context '#validate_value' do
  #     it "raises helpful exception" do
  #       expect { settings.get_setting(canonical_setting_name).validate_value }
  #         .to raise_exception(java.lang.IllegalStateException, a_string_including("Both `#{canonical_setting_name}` and its deprecated alias `#{deprecated_setting_name}` have been set. Please only set `#{canonical_setting_name}`"))
  #     end
  #   end
  # end

  context 'Settings#get on deprecated alias' do
    it 'produces a WARN-level message to the logger' do
      puts "DNADBG>> inside the test"
      settings.get(deprecated_setting_name)
      puts "DNADBG>> inside the test - after exercise"
      expect(events[0].message.formatted_message).to include("setting `#{canonical_setting_name}` has been queried by its deprecated alias `#{deprecated_setting_name}`")
    end
  end
end
