# Changes in version 1.?.? - 2018-0?-??

 * Medium changes
   - Properly clean up sanitized web server logs in the recent/
     directory when they turn older than three days.

 * Minor changes
   - Once more, fix the bug in the tarball-creation script where
     tarballs are not compressed in a run following an aborted run.


# Changes in version 1.7.0 - 2018-07-14

 * Medium changes
   - Recognize new bridge authority Serge.

 * Minor changes
   - Rename root package org.torproject.collector to
     org.torproject.metrics.collector and ..index to ..indexer.
   - Fix a bug in the tarball-creation script where tarballs might not
     have been compressed in a run following an aborted run.
   - Prevent weird values when calculating the cut-off date for
     storing bridge sanitizer secrets using inf as the default value
     of BridgeDescriptorMappingsLimit.


# Changes in version 1.6.0 - 2018-05-23

 * Medium changes
   - Update and adapt to metrics-lib 2.4.0.
   - Replace Gson with Jackson.


# Changes in version 1.5.1 - 2018-03-19

 * Medium changes
   - Add the correct number of lines to sanitized webstats files.

 * Minor changes
   - Add bastet to default list of directory authority fingerprints to
     download votes for.


# Changes in version 1.5.0 - 2018-02-26

 * Major changes
   - Update to metrics-lib 2.2.0.
   - Add new module for processing and sanitizing Tor web server logs.

 * Minor changes
   - Exclude lastModifiedMillis in index.json.


# Changes in version 1.4.1 - 2017-10-26

 * Medium changes
   - Handle bridge descriptors with an unusual order of "published"
     and "fingerprint" lines.
   - Retain "bridge-distribution-request" lines when sanitizing
     descriptors.


# Changes in version 1.4.0 - 2017-10-09

 * Major changes
   - Rename "Onionperf*" configuration options in collector.properties
     to "OnionPerf*" (with capital P).
   - Add "Sync" as OnionPerfSource to synchronize .tpf files from
     other CollecTor instances.

 * Medium changes
   - Add new optional "build_revision" field to index.json with the
     Git revision of the CollecTor instance's software used to create
     this file, which will be omitted if unknown.

 * Minor changes
   - Remove all styling resources (fonts, CSS, etc.) from directory
     listings.


# Changes in version 1.3.0 - 2017-09-15

 * Major changes
   - Update to metrics-lib 2.1.0 and to Java 8.

 * Medium changes
   - When synchronizing descriptors from another CollecTor instance,
     keep annotations provided by the descriptor and only add the
     default annotation, when there was none.


# Changes in version 1.2.1 - 2017-08-17

 * Medium changes
   - Fix a bug while sanitizing bridge network statuses without
     entries.


# Changes in version 1.2.0 - 2017-07-12

 * Major changes
   - Download .tpf files from OnionPerf hosts.
   - Stop downloading and merging .data and .extradata files from
     Torperf hosts.
   - Update to metrics-lib 2.0.0.
   - Update to Debian stretch libraries.

 * Medium changes
   - Clean up files in recent/exit-lists/ again.
   - Retain padding-counts lines in sanitized extra-info descriptors.
   - Either include or retain "fingerprint" line in bridge network
     statuses with @type bridge-network-status 1.2.
   - Set read timeouts for downloads from directory authorities and
     the exit list server.

 * Minor changes
   - Only consider recent relay descriptors in reference checker.


# Changes in version 1.1.2 - 2017-01-17

 * Medium changes
   - Unify the build process by adding git-submodule metrics-base in
     src/build and removing all centralized parts of the build
     process.
   - Use the correct type annotation "@type tordnsel 1.0" for exit
     lists, rather than "@type torperf 1.0".


# Changes in version 1.1.1 - 2016-11-24

 * Medium changes
   - Handle corrupt internal file used for checking references between
     descriptors by deleting and regenerating instead of escalating.
   - Retain hidserv-* lines in sanitized extra-info descriptors.
   - Sign .jar files again, and ensure they get signed in the build
     process.

 * Minor changes
   - Add instructions and sample configuration for using nginx as HTTP
     server rather than Apache.


# Changes in version 1.1.0 - 2016-10-28

 * Major changes
   - Provide a facility to synchronize descriptors from other CollecTor
     instances.  If configured, the synchronization run collects
     recent descriptors from one or more remote CollecTor instances,
     verifies descriptors, and sorts them into the local descriptor
     store.  Synchronization is implemented for relay descriptors
     (except microdescriptors), sanitized bridge descriptors, and exit
     lists.

 * Medium changes
   - Replace four properties for configuring where to write
     descriptors by a single 'OutPath' property.
   - Introduce *Sources and *Origins properties to simplify data
     source definition.
   - Remove six properties for specifying what relay descriptors to
     download and replace them with hard-coded 'true' values.

 * Minor changes
   - Add enum for descriptor type annotations.
   - Add modular file persistence to write descriptors to the out/ and
     recent/ subdirectories..
   - Exclude temporary files from index.json* files.
   - Expand the operator's guide in INSTALL.md.


# Changes in version 1.0.2 - 2016-10-07

 * Medium changes
   - Add support for Bifroest's bridge descriptor tarballs.
   - Use a shutdown hook that gives currently running modules up to 10
     minutes to finish properly, rather than killing them immediately.
   - Replace TCP ports with hashes in @type bridge-network-status 1.1
     and @type bridge-server-descriptor 1.2.
   - Split up bridge descriptor tarballs into one tarball per month
     and descriptor type: bridge-statuses-YYYY-MM.tar.xz,
     bridge-server-descriptors-YYYY-MM.tar.xz and
     bridge-extra-infos-YYYY-MM.tar.xz.
   - Keep "proto" lines in bridge server descriptors as introduced in
     proposal 264.
   - Add tests for the bridgedescs module.
   - Validate bridge tarballs from the bridge authority more
     rigorously.

 * Minor changes
   - Remove quotes around base URL in index.json.
   - Change default log thresholds from TRACE to INFO.
   - Extend checkstyle to also check test sources.


# Changes in version 1.0.1 - 2016-08-22

 * Medium changes
   - Avoid running out of memory when executing the relaydescs module
     repeatedly from the internal scheduler rather than using the
     system's cron daemon.


# Changes in version 1.0.0 - 2016-08-11

 * Major changes
   - This is the initial release after over six and a half years of
     development.

