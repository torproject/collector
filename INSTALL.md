CollecTor -- Operator's Guide
=============================

Welcome to the Operator's Guide of CollecTor.  This guide explains how
to set up a new CollecTor instance to download relay descriptors from the
Tor directory authorities.


Requirements
------------

You'll need a Linux host with at least 50G disk space and 2G RAM.

In the following we'll assume that the host runs Debian stable as
operating system, but it should work on any other Linux or possibly even
*BSD.  Though you'll be mostly on your own with those.

As Java is available on a variety of other operating systems, these might
work, too.  But again you'll be on your own.

Prepare the system
------------------

CollecTor is provided by The Tor Project and can be found here:
    https://dist.torproject.org/collector/
Download the tar.gz file with the version number listed in build.xml.
The README inside the tar.gz file has all the information about CollecTor
and explains how to verify the downloaded files.

You need a Java installation.  On Debian you can just run:

$ sudo apt-get openjdk-7-jdk

Configure the relay descriptor downloader
-----------------------------------------

Run
$ java -DLOGBASE=/path/to/logs -jar collector-<version>.jar
once in order to obtain a configuration properties file.

There are quite a few options to set in collector.properties and the comments
explain their meaning.  So, you can set the options to the values you want.

Create the paths you set in collector.properties.

Example: run the relay descriptor downloader
--------------------------------------------

This is a small example about how CollecTor is used.  All the other
settings are explained in the default collector.properties.

For running the relay descriptor downloader:

Edit collector.properties and set at least the following value to true:

DownloadRelayDescriptors = true

$ java -DLOGBASE=/path/to/logs -jar collector-<version>.jar </place/of/collector.properties>

Watch out for INFO-level logs in the log directory you configured.  In
particular, the lines following "Statistics on the completeness of written
relay descriptors:" are quite important.

In case of the unforeseen ERROR and WARN level logs should help you troubleshoot
your installation.

Maintenance
-----------

CollecTor is designed to keep running and attempts to re-run modules even
when previous runs stopped because of a problem.  Thus, it is very important
to watch out for WARNING level and especially ERROR level log statements.

These often will point to problems you can do something about, e.g. a full disk
or missing file system permissions.

Logging Configuration
---------------------

Some hints for those who are familiar with Logback:

If you want to use your own logging configuration for Logback you can simply
create your own logback.xml or logback.groovy and start CollecTor in the
following way:

java -cp /folder/with/logback:collector-1.0.0.jar org.torproject.collector.Main
 </place/of/collector.properties>

The default configuration can be found in the tar-ball you downloaded, in
the subdirectory collector-1.0.0/src/main/resources.