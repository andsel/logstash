---
mapped_pages:
  - https://www.elastic.co/guide/en/logstash/current/java-output-plugin.html
---

# How to write a Java output plugin [java-output-plugin]

To develop a new Java output for Logstash, you write a new Java class that conforms to the Logstash Java Outputs API, package it, and install it with the logstash-plugin utility. We’ll go through each of those steps.


## Set up your environment [_set_up_your_environment_4]


### Copy the example repo [_copy_the_example_repo_4]

Start by copying the [example output plugin](https://github.com/logstash-plugins/logstash-output-java_output_example). The plugin API is currently part of the Logstash codebase so you must have a local copy of that available. You can obtain a copy of the Logstash codebase with the following `git` command:

```shell
git clone --branch <branch_name> --single-branch https://github.com/elastic/logstash.git <target_folder>
```

The `branch_name` should correspond to the version of Logstash containing the preferred revision of the Java plugin API.

::::{note}
The GA version of the Java plugin API is available in the `7.2` and later branches of the Logstash codebase.
::::


Specify the `target_folder` for your local copy of the Logstash codebase. If you do not specify `target_folder`, it defaults to a new folder called `logstash` under your current folder.


### Generate the .jar file [_generate_the_jar_file_4]

After you have obtained a copy of the appropriate revision of the Logstash codebase, you need to compile it to generate the .jar file containing the Java plugin API. From the root directory of your Logstash codebase ($LS_HOME), you can compile it with `./gradlew assemble` (or `gradlew.bat assemble` if you’re running on Windows). This should produce the `$LS_HOME/logstash-core/build/libs/logstash-core-x.y.z.jar` where `x`, `y`, and `z` refer to the version of Logstash.

After you have successfully compiled Logstash, you need to tell your Java plugin where to find the `logstash-core-x.y.z.jar` file. Create a new file named `gradle.properties` in the root folder of your plugin project. That file should have a single line:

```txt
LOGSTASH_CORE_PATH=<target_folder>/logstash-core
```

where `target_folder` is the root folder of your local copy of the Logstash codebase.


## Code the plugin [_code_the_plugin_4]

The example output plugin prints events to the console using the event’s `toString` method. Let’s look at the main class in the example output:

```java
@LogstashPlugin(name = "java_output_example")
public class JavaOutputExample implements Output {

    public static final PluginConfigSpec<String> PREFIX_CONFIG =
            PluginConfigSpec.stringSetting("prefix", "");

    private final String id;
    private String prefix;
    private PrintStream printer;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile boolean stopped = false;

    public JavaOutputExample(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out);
    }

    JavaOutputExample(final String id, final Configuration config, final Context context, OutputStream targetStream) {
        this.id = id;
        prefix = config.get(PREFIX_CONFIG);
        printer = new PrintStream(targetStream);
    }

    @Override
    public void output(final Collection<Event> events) {
      Iterator<Event> z = events.iterator();
      while (z.hasNext() && !stopped) {
          String s = prefix + z.next();
          printer.println(s);
        }
    }

    @Override
    public void stop() {
        stopped = true;
        done.countDown();
    }

    @Override
    public void awaitStop() throws InterruptedException {
        done.await();
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return Collections.singletonList(PREFIX_CONFIG);
    }

    @Override
    public String getId() {
        return id;
    }
}
```

Let’s step through and examine each part of that class.


### Class declaration [_class_declaration_8]

```java
@LogstashPlugin(name="java_output_example")
public class JavaOutputExample implements Output {
```

Notes about the class declaration:

* All Java plugins must be annotated with the `@LogstashPlugin` annotation. Additionally:

    * The `name` property of the annotation must be supplied and defines the name of the plugin as it will be used in the Logstash pipeline definition. For example, this output would be referenced in the output section of the Logstash pipeline definition as `output { java_output_example => { .... } }`
    * The value of the `name` property must match the name of the class excluding casing and underscores.

* The class must implement the `co.elastic.logstash.api.Output` interface.
* Java plugins may not be created in the `org.logstash` or `co.elastic.logstash` packages to prevent potential clashes with classes in Logstash itself.


### Plugin settings [_plugin_settings_4]

The snippet below contains both the setting definition and the method referencing it:

```java
public static final PluginConfigSpec<String> PREFIX_CONFIG =
        PluginConfigSpec.stringSetting("prefix", "");

@Override
public Collection<PluginConfigSpec<?>> configSchema() {
    return Collections.singletonList(PREFIX_CONFIG);
}
```

The `PluginConfigSpec` class allows developers to specify the settings that a plugin supports complete with setting  name, data type, deprecation status, required status, and default value. In this example, the `prefix` setting defines an optional prefix to include in the output of the event. The setting is not required and if it is not explicitly set, it defaults to the empty string.

The `configSchema` method must return a list of all settings that the plugin supports. In a future phase of the Java plugin project, the Logstash execution engine will validate that all required settings are present and that no unsupported settings are present.


### Constructor and initialization [_constructor_and_initialization_4]

```java
private final String id;
private String prefix;
private PrintStream printer;

public JavaOutputExample(final String id, final Configuration configuration, final Context context) {
    this(configuration, context, System.out);
}

JavaOutputExample(final String id, final Configuration config, final Context context, OutputStream targetStream) {
    this.id = id;
    prefix = config.get(PREFIX_CONFIG);
    printer = new PrintStream(targetStream);
}
```

All Java output plugins must have a constructor taking a `String` id and a `Configuration` and `Context` argument. This is the constructor that will be used to instantiate them at runtime. The retrieval and validation of all plugin settings should occur in this constructor. In this example, the values of the `prefix` setting is retrieved and stored in a local variable for later use in the `output` method. In this example, a second, pacakge private constructor is defined that is useful for unit testing with a `Stream` other than `System.out`.

Any additional initialization may occur in the constructor as well. If there are any unrecoverable errors encountered in the configuration or initialization of the output plugin, a descriptive exception should be thrown. The exception will be logged and will prevent Logstash from starting.


### Output method [_output_method]

```java
@Override
public void output(final Collection<Event> events) {
    Iterator<Event> z = events.iterator();
    while (z.hasNext() && !stopped) {
        String s = prefix + z.next();
        printer.println(s);
    }
}
```

Outputs may send events to local sinks such as the console or a file or to remote systems such as Elasticsearch or other external systems. In this example, the events are printed to the local console.


### Stop and awaitStop methods [_stop_and_awaitstop_methods_2]

```java
private final CountDownLatch done = new CountDownLatch(1);
private volatile boolean stopped;

@Override
public void stop() {
    stopped = true;
    done.countDown();
}

@Override
public void awaitStop() throws InterruptedException {
    done.await();
}
```

The `stop` method notifies the output to stop sending events. The stop mechanism may be implemented in any way that honors the API contract though a `volatile boolean` flag works well for many use cases. Because this output example is so simple, its `output` method does not check for the stop flag.

Outputs stop both asynchronously and cooperatively. Use the `awaitStop` method to block until the output has  completed the stop process. Note that this method should **not** signal the output to stop as the `stop` method  does. The awaitStop mechanism may be implemented in any way that honors the API contract though a `CountDownLatch` works well for many use cases.


### getId method [_getid_method_4]

```java
@Override
public String getId() {
    return id;
}
```

For output plugins, the `getId` method should always return the id that was provided to the plugin through its constructor at instantiation time.


### Unit tests [_unit_tests_4]

Lastly, but certainly not least importantly, unit tests are strongly encouraged. The example output plugin includes an [example unit test](https://github.com/logstash-plugins/logstash-output-java_output_example/blob/main/src/test/java/org/logstashplugins/JavaOutputExampleTest.java) that you can use as a template for your own.


## Package and deploy [_package_and_deploy_4]

Java plugins are packaged as Ruby gems for dependency management and interoperability with Ruby plugins. Once they are packaged as gems, they may be installed with the `logstash-plugin` utility just as Ruby plugins are. Because no knowledge of Ruby or its toolchain should be required for Java plugin development, the procedure for packaging Java plugins as Ruby gems has been automated through a custom task in the Gradle build file provided with the example Java plugins. The following sections describe how to configure and execute that packaging task as well as how to install the packaged Java plugin in Logstash.


### Configuring the Gradle packaging task [_configuring_the_gradle_packaging_task_4]

The following section appears near the top of the `build.gradle` file supplied with the example Java plugins:

```java
// ===========================================================================
// plugin info
// ===========================================================================
group                      'org.logstashplugins' // must match the package of the main plugin class
version                    "${file("VERSION").text.trim()}" // read from required VERSION file
description                = "Example Java filter implementation"
pluginInfo.licenses        = ['Apache-2.0'] // list of SPDX license IDs
pluginInfo.longDescription = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using \$LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
pluginInfo.authors         = ['Elasticsearch']
pluginInfo.email           = ['info@elastic.co']
pluginInfo.homepage        = "http://www.elastic.co/guide/en/logstash/current/index.html"
pluginInfo.pluginType      = "filter"
pluginInfo.pluginClass     = "JavaFilterExample"
pluginInfo.pluginName      = "java_filter_example"
// ===========================================================================
```

You should configure the values above for your plugin.

* The `version` value will be automatically read from the `VERSION` file in the root of your plugin’s codebase.
* `pluginInfo.pluginType` should be set to one of `input`, `filter`, `codec`, or `output`.
* `pluginInfo.pluginName` must match the name specified on the `@LogstashPlugin` annotation on the main plugin class. The Gradle packaging task will validate that and return an error if they do not match.


### Running the Gradle packaging task [_running_the_gradle_packaging_task_4]

Several Ruby source files along with a `gemspec` file and a `Gemfile` are required to package the plugin as a Ruby gem. These Ruby files are used only for defining the Ruby gem structure or at Logstash startup time to register the Java plugin. They are not used during runtime event processing. The Gradle packaging task automatically generates all of these files based on the values configured in the section above.

You run the Gradle packaging task with the following command:

```shell
./gradlew gem
```

For Windows platforms: Substitute `gradlew.bat` for `./gradlew` as appropriate in the command.

That task will produce a gem file in the root directory of your plugin’s codebase with the name `logstash-{{plugintype}}-<pluginName>-<version>.gem`


### Installing the Java plugin in Logstash [_installing_the_java_plugin_in_logstash_4]

After you have packaged your Java plugin as a Ruby gem, you can install it in Logstash with this command:

```shell
bin/logstash-plugin install --no-verify --local /path/to/javaPlugin.gem
```

For Windows platforms: Substitute backslashes for forward slashes as appropriate in the command.


## Running Logstash with the Java output plugin [_running_logstash_with_the_java_output_plugin]

The following is a minimal Logstash configuration that can be used to test that the Java output plugin is correctly installed and functioning.

```java
input {
  generator { message => "Hello world!" count => 1 }
}
output {
  java_output_example {}
}
```

Copy the above Logstash configuration to a file such as `java_output.conf`. Logstash should then be started with:

```txt
bin/logstash -f /path/to/java_output.conf
```

The expected Logstash output (excluding initialization) with the configuration above is:

```txt
{"@timestamp":"yyyy-MM-ddTHH:mm:ss.SSSZ","message":"Hello world!","@version":"1","host":"<yourHostname>","sequence":0}
```


## Feedback [_feedback_4]

If you have any feedback on Java plugin support in Logstash, please comment on our [main Github issue](https://github.com/elastic/logstash/issues/9215) or post in the [Logstash forum](https://discuss.elastic.co/c/logstash).
