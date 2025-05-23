---
mapped_pages:
  - https://www.elastic.co/guide/en/logstash/current/logging.html
---

# Logging [logging]

Logstash emits internal logs during its operation, which are placed in `LS_HOME/logs` (or `/var/log/logstash` for DEB/RPM). The default logging level is `INFO`. Logstash’s logging framework is based on [Log4j 2 framework](http://logging.apache.org/log4j/2.x/), and much of its functionality is exposed directly to users.

You can configure logging for a particular subsystem, module, or plugin.

When you need to debug problems, particularly problems with plugins, consider increasing the logging level to `DEBUG` to get more verbose messages. For example, if you are debugging issues with Elasticsearch Output, you can increase log levels just for that component. This approach reduces noise from excessive logging and helps you focus on the problem area.

You can configure logging using the `log4j2.properties` file or the Logstash API.

* **`log4j2.properties` file.**  Changes made through the `log4j2.properties` file require you to restart Logstash for the changes to take effect.  Changes **persist** through subsequent restarts.
* **Logging API.** Changes made through the Logging API are effective immediately without a restart. The changes **do not persist** after Logstash is restarted.

## Log4j2 configuration [log4j2]

Logstash ships with a `log4j2.properties` file with out-of-the-box settings, including logging to console. You can modify this file to change the rotation policy, type, and other [log4j2 configuration](https://logging.apache.org/log4j/2.x/manual/configuration.html#Loggers).

You must restart Logstash to apply any changes that you make to this file. Changes to `log4j2.properties` persist after Logstash is restarted.

Here’s an example using `outputs.elasticsearch`:

```yaml
logger.elasticsearchoutput.name = logstash.outputs.elasticsearch
logger.elasticsearchoutput.level = debug
```

The previous example defines a name and level for the logger `logstash.outputs.elasticsearch`. The logger is usually identified by a Java class name, such as `org.logstash.dissect.Dissector`, for example.  It can also be a partial package path as in `org.logstash.dissect`.  For Ruby classes, like `LogStash::Outputs::Elasticsearch`, the logger name is obtained by lowercasing the full class name and replacing double colons with a single dot.

::::{note}
Consider using the default log4j configuration that is shipped with {{ls}}, as it is configured to work well for most deployments. The next section describes how the rolling strategy works in case you need to make adjustments.
::::


### Rollover settings [rollover]

The `log4j2.properties` file has three appenders for writing to log files: one for plain text, one with json format, and one to split log lines on per pipeline basis when you set the `pipeline.separate_logs` value.

These appenders define:

* **triggering policies** that determine *if* a rollover should be performed, and
* **rollover strategy**  to defines *how* the rollover should be done.

By default, two triggering policies are defined—​time and size.

* The **time** policy creates one file per day.
* The **size** policy forces the creation of a new file after the file size surpasses 100 MB.

The default strategy also performs file rollovers based on a **maximum number of files**. When the limit of 30 files has been reached, the first (oldest) file is removed to create space for the new file. Subsequent files are renumbered accordingly.

Each file has a date, and files older than 7 days (default) are removed during rollover.

```text
appender.rolling.type = RollingFile <1>
appender.rolling.name = plain_rolling
appender.rolling.fileName = ${sys:ls.logs}/logstash-plain.log <2>
appender.rolling.filePattern = ${sys:ls.logs}/logstash-plain-%d{yyyy-MM-dd}-%i.log.gz <3>
appender.rolling.policies.type = Policies
appender.rolling.policies.time.type = TimeBasedTriggeringPolicy <4>
appender.rolling.policies.time.interval = 1
appender.rolling.policies.time.modulate = true
appender.rolling.layout.type = PatternLayout
appender.rolling.layout.pattern = [%d{ISO8601}][%-5p][%-25c]%notEmpty{[%X{pipeline.id}]}%notEmpty{[%X{plugin.id}]} %m%n
appender.rolling.policies.size.type = SizeBasedTriggeringPolicy <5>
appender.rolling.policies.size.size = 100MB
appender.rolling.strategy.type = DefaultRolloverStrategy
appender.rolling.strategy.max = 30 <6>
appender.rolling.strategy.action.type = Delete <7>
appender.rolling.strategy.action.basepath = ${sys:ls.logs}
appender.rolling.strategy.action.condition.type = IfFileName
appender.rolling.strategy.action.condition.glob = logstash-plain-* <8>
appender.rolling.strategy.action.condition.nested_condition.type = IfLastModified
appender.rolling.strategy.action.condition.nested_condition.age = 7D <9>
```

1. The appender type, which rolls older log files.
2. Name of the current log file.
3. Name’s format definition of the rolled files, in this case a date followed by an incremental number, up to 30 (by default).
4. Time policy to trigger a rollover at the end of the day.
5. Size policy to trigger a rollover once the plain text file reaches the size of 100 MB.
6. Rollover strategy defines a maximum of 30 files.
7. Action to execute during the rollover.
8. The file set to consider by the action.
9. Condition to execute the rollover action: older than 7 days.


The rollover action can also enforce a disk usage limit, deleting older files to match the requested condition, as an example:

```text
appender.rolling.type = RollingFile
...
appender.rolling.strategy.action.condition.glob = pipeline_${ctx:pipeline.id}.*.log.gz
appender.rolling.strategy.action.condition.nested_condition.type = IfAccumulatedFileSize
appender.rolling.strategy.action.condition.nested_condition.exceeds = 5MB <1>
```

1. Deletes files if total accumulated compressed file size is over 5MB.




## Logging APIs [_logging_apis]

For temporary logging changes, modifying the `log4j2.properties` file and restarting Logstash leads to unnecessary downtime. Instead, you can dynamically update logging levels through the logging API. These settings are effective immediately and do not need a restart.

::::{note}
By default, the logging API attempts to bind to `tcp:9600`. If this port is already in use by another Logstash instance, you need to launch Logstash with the `--api.http.port` flag specified to bind to a different port. See [Command-Line Flags](/reference/running-logstash-command-line.md#command-line-flags) for more information.
::::


### Retrieve list of logging configurations [_retrieve_list_of_logging_configurations]

To retrieve a list of logging subsystems available at runtime, you can do a `GET` request to `_node/logging`

```js
curl -XGET 'localhost:9600/_node/logging?pretty'
```

Example response:

```js
{
...
  "loggers" : {
    "logstash.agent" : "INFO",
    "logstash.api.service" : "INFO",
    "logstash.basepipeline" : "INFO",
    "logstash.codecs.plain" : "INFO",
    "logstash.codecs.rubydebug" : "INFO",
    "logstash.filters.grok" : "INFO",
    "logstash.inputs.beats" : "INFO",
    "logstash.instrument.periodicpoller.jvm" : "INFO",
    "logstash.instrument.periodicpoller.os" : "INFO",
    "logstash.instrument.periodicpoller.persistentqueue" : "INFO",
    "logstash.outputs.stdout" : "INFO",
    "logstash.pipeline" : "INFO",
    "logstash.plugins.registry" : "INFO",
    "logstash.runner" : "INFO",
    "logstash.shutdownwatcher" : "INFO",
    "org.logstash.Event" : "INFO",
    "slowlog.logstash.codecs.plain" : "TRACE",
    "slowlog.logstash.codecs.rubydebug" : "TRACE",
    "slowlog.logstash.filters.grok" : "TRACE",
    "slowlog.logstash.inputs.beats" : "TRACE",
    "slowlog.logstash.outputs.stdout" : "TRACE"
  }
}
```


### Update logging levels [_update_logging_levels]

Prepend the name of the subsystem, module, or plugin with `logger.`.

Here is an example using `outputs.elasticsearch`:

```js
curl -XPUT 'localhost:9600/_node/logging?pretty' -H 'Content-Type: application/json' -d'
{
    "logger.logstash.outputs.elasticsearch" : "DEBUG"
}
'
```

While this setting is in effect, Logstash emits DEBUG-level logs for *all* the Elasticsearch outputs specified in your configuration. Please note this new setting is transient and will not survive a restart.

::::{note}
If you want logging changes to persist after a restart, add them to `log4j2.properties` instead.
::::



### Reset dynamic logging levels [_reset_dynamic_logging_levels]

To reset any logging levels that may have been dynamically changed via the logging API, send a `PUT` request to `_node/logging/reset`. All logging levels will revert to the values specified in the `log4j2.properties` file.

```js
curl -XPUT 'localhost:9600/_node/logging/reset?pretty'
```



## Log file location [_log_file_location]

You can specify the log file location using `--path.logs` setting.


## Slowlog [_slowlog]

Slowlog for Logstash adds the ability to log when a specific event takes an abnormal amount of time to make its way through the pipeline. Just like the normal application log, you can find slowlogs in your `--path.logs` directory. Slowlog is configured in the `logstash.yml` settings file with the following options:

```yaml
slowlog.threshold.warn (default: -1)
slowlog.threshold.info (default: -1)
slowlog.threshold.debug (default: -1)
slowlog.threshold.trace (default: -1)
```

Slowlog is disabled by default. The default threshold values are set to `-1nanos` to represent an infinite threshold. No slowlog will be invoked.

### Enable slowlog [_enable_slowlog]

The `slowlog.threshold` fields use a time-value format which enables a wide range of trigger intervals. You can specify ranges using the following time units: `nanos` (nanoseconds), `micros` (microseconds), `ms` (milliseconds), `s` (second), `m` (minute), `h` (hour), `d` (day).

Slowlog becomes more sensitive and logs more events as you raise the log level.

Example:

```yaml
slowlog.threshold.warn: 2s
slowlog.threshold.info: 1s
slowlog.threshold.debug: 500ms
slowlog.threshold.trace: 100ms
```

In this example:

* If the log level is set to `warn`, the log shows events that took longer than 2s to process.
* If the log level is set to `info`, the log shows events that took longer than 1s to process.
* If the log level is set to `debug`, the log shows events that took longer than 500ms to process.
* If the log level is set to `trace`, the log shows events that took longer than 100ms to process.

The logs include the full event and filter configuration that are responsible for the slowness.
