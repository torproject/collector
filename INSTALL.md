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
$ sudo chown vagrant:vagrant /srv/collector.torproject.org/

Install a few packages:

$ sudo apt-get install openjdk-6-jdk ant libcommons-codec-java \
  libcommons-compress-java


Clone the metrics-db repository
-------------------------------

$ cd /srv/collector.torproject.org/
$ git clone https://git.torproject.org/metrics-db


Clone required submodule metrics-lib
------------------------------------

$ git submodule init
$ git submodule update


Compile CollecTor
-----------------

$ ant compile


Configure the relay descriptor downloader
-----------------------------------------

Edit the config file and uncomment and edit at least the following line:

DownloadRelayDescriptors 1


Run the relay descriptor downloader
-----------------------------------

$ bin/run-relaydescs


Set up an hourly cronjob for the relay descriptor downloader
------------------------------------------------------------

Ideally, run the relay descriptor downloader once per hour by adding a
crontab entry like the following:

6 * * * * cd /srv/collector.torproject.org/db/ && bin/run-relaydescs

Watch out for INFO-level logs in the `log/` directory.  In particular, the
lines following "Statistics on the completeness of written relay
descriptors:" is quite important.

