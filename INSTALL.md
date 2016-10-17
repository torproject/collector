# CollecTor Operator's Guide

Welcome to CollecTor, your friendly data-collecting service in the Tor network.
CollecTor fetches data from various nodes and services in the public Tor network
and makes it available to the world.  This data includes relay descriptors from
the directory authorities, sanitized bridge descriptors from the bridge
authority, and other data about the Tor network.

This document describes how to set up your very own CollecTor instance.  It was
written with an audience in mind that has at least some experience with running
services and is comfortable with the command line.  It's not required that you
know how to read or even write Java code, though.

Before we go ahead with setting up your CollecTor instance, let us pause for a
moment and reflect why you'd want to do that as opposed to simply using data
from an existing CollecTor instance.

CollecTor is a service, and the best reason for running a CollecTor service
instance is to offer your collected Tor network data to others.  You could
mirror the data from an existing instance or even aggregate data from multiple
instances by using the synchronization feature.  Or you could fetch data from
public sources and provide your data to users and other CollecTor instances.
Another reason might be to collect or synchronize Tor network data and provide
it to your working or research group.  And of course you might want to run a
CollecTor instance for testing purposes.  In all these cases, setting up a
CollecTor instance might make sense.

However, if you only want to use Tor network data as a client, even as input for
another service you're developing, you don't have to and probably shouldn't run
a CollecTor instance.  In that case it's sufficient to use a library like
[metrics-lib](https://dist.torproject.org/descriptor/) or
[Stem](https://stem.torproject.org/) to fetch CollecTor data and process it.


## Setting up the host

You'll need a host with at least 200G disk space and 4G RAM.

In the following we'll assume that your host runs Debian stable as operating
system.  CollecTor should run on any other Linux or possibly even *BSD, though
you'll be mostly on your own with those.  And as Java is available on a variety
of other operating systems, those might work, too, but, again, you'll be on your
own.

CollecTor does not require installing many or specific dependencies on the host
system.  All it needs are a Java Runtime Environment version 7 or higher and an
Apache HTTP Server version 2 or higher.

The CollecTor service runs entirely under a non-privileged user account.  Any
user account will do, but feel free to create a new user account just for the
CollecTor service, if you prefer.

The CollecTor service requires running in a working directory where it can store
Tor network data and state files.  This working directory can be located
anywhere in the file system as long as there is enough disk space available.
The Apache service will later need to know where to find files to serve to web
clients including other CollecTor instances.

CollecTor does not require setting up a database.

This concludes the host setup.  Later in the process you'll once more need root
privileges to configure Apache to serve CollecTor files.  But until then you can
do all setup steps with the non-privileged user account.


## Setting up the service

### Obtaining the code

CollecTor releases are available at:

```https://dist.torproject.org/collector/```

Choose the latest tarball and signature file, verify the signature on the
tarball, and extract the tarball in a location of your choice which will create
a subdirectory called `collector-<version>/`.


### Planning the service setup

By default, CollecTor is configured to do nothing at all.  The reason is that
new operators should first understand its capabilities and make a plan for
configuring their new CollecTor instance.  Let's do that now.

CollecTor consists of a background updater with an internal scheduler and
several data-collecting modules that write data to local directories which are
then served by a webserver.  Each of the modules can have one or more data
sources, some public like relay descriptors served by the directory authorities
and some private like bridge descriptors uploaded to the bridge directory
authority.

You'll have to decide which of the data-collecting modules you want to activate,
how often to execute these modules, and which data sources to collect data from.

The release tarball contains an executable .jar file:

```collector-<version>/generated/dist/collector-<version>.jar```

Copy this .jar file into the working directory and run it:

```java -jar collector-<version>.jar```

CollecTor will print some text about not being able to find a configuration
file, which is understandable since there is no such file yet.  It also writes a
fresh configuration file called `collector.properties` to the working directory
which contains defaults (that instruct CollecTor to do nothing).

Read through that file to learn about all available configuration options.


### Performing the initial run

When you have made a plan how to configure your CollecTor instance, edit the
`collector.properties` file, set it to run only once, activate all relevant
modules, check and possibly edit other options as needed, and save the file.
Run the Java process using:

```java -Xmx2g -DLOGBASE=<your-log-dir> -jar collector-<version>.jar
<your-collector.properties>```

The option `-Xmx2g` sets the maximum heap space to 2G, which is based on the
recommended 4G total RAM size for the host.  If you have more memory to spare,
feel free to adapt this option as needed.

This may take a while, depending on which modules you activated.  Read the logs
to learn if the run was successful.  If it wasn't, go back to editing the
properties file and re-run the .jar file.  Change the run-once option back when
you're done with the initial run of the Java process.

Complete the initialization step by copying the shell script
`collector-<version>/src/main/resources/create-tarballs.sh` from the release
tarball to the working directory or another location of your choice, editing the
contained paths, and executing it.  Note that this script will at least partly
fail if one or more modules are deactivated.


### Scheduling periodic runs

The next step in setting up the CollecTor instance is to start the updater with
its internal scheduler and let it run continuously in the background.  In order
to do so, make sure the run-once property is set to `false`, possibly adapt the
scheduling properties, and execute the .jar file using the same command as above
but this time in the background.  Make sure that the same command will be run
automatically after a reboot.

Also make sure that the `create-tarballs.sh` script will be executed at least
every three days, but no more than once per day.

### Setting up the website

The last remaining part in the setup process is to make the collected data
available.  Copy the contents from `collector-<version>/src/main/webapp/*` in
the release tarball to a web application subdirectory in the working directory
or another location of your choice.

Configure an Apache site that uses redirects or symbolic links to serve the
following directories or files in your working directory (where paths in <>
refer to settings in `collector.properties`):

 * `<your-webapp-dir>/*`,
 * `<ArchivePath>`,
 * `<IndexPath>`, and
 * `<RecentPath>`.

Use your browser to make sure that your instance serves the web pages and data
that you'd expect.


## Maintaining the service

### Monitoring the service

The most important information about your CollecTor instance is whether it is
alive.  Otherwise, if it dies and you don't notice, you might be losing data
that is not available at the data sources anymore.  You should set up a
notification mechanism of your choice to be informed quickly when the background
updater dies.

Other than fatal issues, a good source for learning about issues with your
CollecTor instance are its logs.  Be sure to read the logs every now and then,
and look out for warnings and errors.  Maybe set up another notification to be
informed quickly of new warnings or errors.


### Changing logging options

CollecTor uses Logback for logging and comes with a default logging
configuration that logs on info level and that creates a common log file that
rotates once per day and a separate log file per module.  If you want to change
logging options, copy the default logging configuration from
`collector-<version>/src/main/resources/logback.xml` to your working directory,
edit your copy, and execute the .jar file as follows:

```java -Xmx2g -DLOGBASE=<your-log-dir> -jar -cp .:collector-<version>.jar
org.torproject.collector.Main```

Internally, CollecTor uses the Simple Logging Facade for Java (SLF4J) and ships
with the Logback implementation for SLF4J.  If you prefer a different logging
framework, you can provide and use that instead.  For more detailed information,
or if you have different logging needs, please refer to the [Logback
documentation](http://logback.qos.ch/), and for switching to a different
framework to the [SFL4J website](http://www.slf4j.org/).


### Changing configuration options

If you need to reconfigure your CollecTor instance, you may be able to do that
without stopping and restarting the Java process.  Scheduling settings are
exempt from this, but all general and module settings may be changed at
run-time.  Just edit the config file, and the changes will become effective in
the next execution of a module.  Changes to the scheduler, however, require
stopping and restarting the Java update process.


### Stopping the service (gracefully)

If you need to stop the background updater for some reason, like rebooting the
host, there is a way to do that gracefully: kill the Java process, and a
shutdown hook will stop the internal scheduler and wait for up to 10 minutes (or
whatever amount of time is configured) for all currently running updates to be
finished.  However, if you must stop the process immediately, use `kill -9`,
though you might have to clean up manually.  You should try to avoid rebooting
while tarballs are being created.


### Upgrading and downgrading

If you need to upgrade to a newer release or downgrade to a previous release,
download that tarball and extract it, and copy over the executable .jar file and
the `create-tarballs.sh` script in case it has changed.  Stop the current
service version as described above, possibly adapt your `collector.properties`
file as necessary, and restart the Java process using the new .jar file.  Don't
forget to update the version number in the command that ensures that the .jar
file gets executed automatically after a reboot.  Watch the logs to see if the
upgrade or downgrade was successful.


### Backing up data and settings

A backup of your CollecTor instance should include the <ArchivePath> and your
configuration, which would enable you to set up this instance again.  A backup
for short term recovery would also include the more volatile data in
<StatsPath>, <RecentPath>, and <OutputPath>.


### Performing recurring tasks

Most of CollecTor is designed to just run in the background forever.  However,
some parts still require manual housekeeping every month or two: You'll need to
clean up data from `<OutputPath>` as configured in `collector.properties` when
you're certain that the data is contained in tarballs and contained in backups.
Likewise, you'll have to delete old files from `<BridgeLocalOrigins>`, in case
that is being used, where CollecTor only reads and never writes or deletes.


### Resolving common issues

Unfortunately, CollecTor still runs into issues from time to time, and some of
these issues require a human being to decide whether they're harmless or require
intervention by the operator.

The most common issue these days is a warning about missing too many referenced
descriptors, which may even be true but which is typically not an operations
issue.

A lot less frequently, the bridgedesc module reports unrecognized lines in
non-sanitized bridge descriptors which, if true, requires developing and
deploying a patch.  And sometimes the bridgedesc module complains about stale
input data, which requires fixing the bridge authority or the sync mechanism to
the CollecTor host.

Another minor issue is that files in `<OutputPath>` may change while tarballs
are being created, which is usually safe to ignore.

There's another frequent error message where CollecTor complains about not being
able to fetch a remote file during the sync process.  This error message is
usually harmless and can be ignored.

But let's hope that you won't run into any of these issues or at least not
frequently.  Enjoy your new CollecTor instance!

