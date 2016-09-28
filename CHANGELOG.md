# Changes in version 1.1.0 - 2016-09-xx

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

 * Minor changes
   - Remove quotes around base URL in index.json.
   - Change default log thresholds from TRACE to INFO.


# Changes in version 1.0.1 - 2016-08-22

 * Medium changes
   - Avoid running out of memory when executing the relaydescs module
     repeatedly from the internal scheduler rather than using the
     system's cron daemon.


# Changes in version 1.0.0 - 2016-08-11

 * Major changes
   - This is the initial release after over six and a half years of
     development.

