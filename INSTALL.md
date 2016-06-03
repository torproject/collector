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


Prepare the system
------------------

Create a working directory for CollecTor.  In this guide, we'll assume
that you're using `/srv/collector.torproject.org/` as working directory,
but feel free to use another directory that better suits your needs.

$ sudo mkdir -p /srv/collector.torproject.org/

Install a few packages:

$ sudo apt-get ant junit4 libasm4-java libcommons-codec-java \
  libcommons-compress-java libcommons-lang3-java libgoogle-gson-java \
  liblogback-java liboro-java libslf4j-java libxz-java openjdk-7-jdk


Compile CollecTor
-----------------

$ ant compile


Configure the relay descriptor downloader
-----------------------------------------

Run
$ java -DLOGBASE=/path/to/logs -jar collector-<version>.jar releaydescs
once in order to obtain a configuration properties file.

Edit collector.properties and set at least the following value to true:

DownloadRelayDescriptors = true


Run the relay descriptor downloader
-----------------------------------

$ java -DLOGBASE=/path/to/logs -jar collector-<version>.jar releaydescs

Watch out for INFO-level logs in the log directory you configured.  In particular, the
lines following "Statistics on the completeness of written relay
descriptors:" is quite important.

