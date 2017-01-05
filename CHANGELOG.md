# Changes in version x.x.x - 2017-xx-xx

 * Medium changes
   - Unify the build process by adding git-submodule metrics-base in
     src/build and removing all centralized parts of the build
     process.


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

