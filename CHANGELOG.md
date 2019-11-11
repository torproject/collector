# Changes in version 1.1?.? - 2019-1?-??


# Changes in version 1.13.1 - 2019-11-11

 * Minor changes
   - Update to metrics-lib 2.9.1.


# Changes in version 1.13.0 - 2019-11-09

 * Medium changes
   - Extend index.json by including descriptor types, first and last
     publication timestamp, and SHA-256 file digest. Requires making
     configuration changes in collector.properties:
      1) IndexedPath is a new directory with subdirectories for
         archived and recent descriptors,
      2) ArchivePath and IndexPath are hard-wired to be subdirectories
         of IndexedPath,
      3) RecentPath must be set to be a subdirectory of IndexedPath,
      4) ContribPath has disappeared, and
      5) HtdocsPath is a new directory with files served by the web
         server.
   - Tweak BridgeDB metrics file names.
   - Update to metrics-lib 2.9.0.


# Changes in version 1.12.0 - 2019-10-18

 * Medium changes
   - Require Mockito 1.10.19 as dependency for running tests.
   - Archive BridgeDB statistics.
   - Update to metrics-lib 2.8.0.


# Changes in version 1.11.1 - 2019-09-19

 * Minor changes
   - Update create-tarballs.sh to also produce bridge pool assignments
     tarballs.
   - Fix synchronization part of newly re-added bridge pool
     assignments module.


# Changes in version 1.11.0 - 2019-09-19

 * Medium changes
   - Archive bridge pool assignments again.


# Changes in version 1.10.0 - 2019-09-12

 * Medium changes
   - Changed local import of bandwidth files to include the parent
     directory name as @source annotation and to the filename.
   - Use Ivy for resolving external dependencies rather than relying
     on files found in Debian stable packages. Requires installing Ivy
     (using `apt-get install ivy`, `brew install ivy`, or similar) and
     running `ant resolve` (or `ant -lib /usr/share/java resolve`).
     Retrieved files are then copied to the `lib/` directory, except
     for dependencies on other metrics libraries that still need to be
     copied to the `lib/` directory manually. Current dependency
     versions resolved by Ivy are the same as in Debian stretch with
     few exceptions.
   - Remove Cobertura from the build process.
   - Archive snowflake statistics.
   - Update to metrics-lib 2.7.0.


# Changes in version 1.9.1 - 2019-05-29

 * Medium changes
   - Fix synchronizing bandwidth files from other CollecTors.
   - Update to metrics-lib 2.6.2.


# Changes in version 1.9.0 - 2019-05-13

 * Medium changes
   - Stop signing jar files.
   - Archive bandwidth files in relaydescs module.
   - Update to metrics-lib 2.6.1.


# Changes in version 1.8.0 - 2018-10-11

 * Medium changes
   - Properly clean up sanitized web server logs in the recent/
     directory when they turn older than three days.

 * Minor changes
   - Once more, fix the bug in the tarball-creation script where
     tarballs are not compressed in a run following an aborted run.
   - Improve logging to find possible issue with missing server
     descriptors.
   - Update directory authority IP addresses in default properties
     file.


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

