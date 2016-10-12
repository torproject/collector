# Changes in version 1.1.0 - 2016-10-XX

 * Medium changes
   - Replace four properties for configuring where to write
     descriptors by a single 'OutPath' property.
   - Introduced *Sources and *Origins properties to simplify
     data source definition.


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

