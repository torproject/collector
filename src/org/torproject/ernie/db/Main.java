/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.File;
import java.util.List;
import java.util.logging.Logger;

/**
 * Coordinate downloading and parsing of descriptors and extraction of
 * statistically relevant data for later processing with R.
 */
public class Main {
  public static void main(String[] args) {

    /* Initialize logging configuration. */
    new LoggingConfiguration();

    Logger logger = Logger.getLogger(Main.class.getName());
    logger.info("Starting ERNIE.");

    // Initialize configuration
    Configuration config = new Configuration();

    // Use lock file to avoid overlapping runs
    LockFile lf = new LockFile();
    if (!lf.acquireLock()) {
      logger.severe("Warning: ERNIE is already running or has not exited "
          + "cleanly! Exiting!");
      System.exit(1);
    }

    // Define stats directory for temporary files
    File statsDirectory = new File("stats");

    // Prepare writing relay descriptor archive to disk
    ArchiveWriter aw = config.getWriteDirectoryArchives() ?
        new ArchiveWriter(
        new File(config.getDirectoryArchivesOutputDirectory())) : null;

    // Prepare relay descriptor parser (only if we are writing stats or
    // directory archives to disk)
    RelayDescriptorParser rdp = aw != null ?
        new RelayDescriptorParser(aw) : null;

    // Import/download relay descriptors from the various sources
    if (rdp != null) {
      RelayDescriptorDownloader rdd = null;
      if (config.getDownloadRelayDescriptors()) {
        List<String> dirSources =
            config.getDownloadFromDirectoryAuthorities();
        rdd = new RelayDescriptorDownloader(rdp, dirSources,
            config.getDownloadCurrentConsensus(),
            config.getDownloadCurrentVotes(),
            config.getDownloadMissingServerDescriptors(),
            config.getDownloadMissingExtraInfoDescriptors(),
            config.getDownloadAllServerDescriptors(),
            config.getDownloadAllExtraInfoDescriptors(),
            config.getCompressRelayDescriptorDownloads());
        rdp.setRelayDescriptorDownloader(rdd);
      }
      if (config.getImportCachedRelayDescriptors()) {
        new CachedRelayDescriptorReader(rdp,
            config.getCachedRelayDescriptorDirectory(), statsDirectory);
        if (aw != null) {
          aw.intermediateStats("importing relay descriptors from local "
              + "Tor data directories");
        }
      }
      if (config.getImportDirectoryArchives()) {
        new ArchiveReader(rdp,
            new File(config.getDirectoryArchivesDirectory()),
            statsDirectory,
            config.getKeepDirectoryArchiveImportHistory());
        if (aw != null) {
          aw.intermediateStats("importing relay descriptors from local "
              + "directory");
        }
      }
      if (rdd != null) {
        rdd.downloadDescriptors();
        rdd.writeFile();
        rdd = null;
        if (aw != null) {
          aw.intermediateStats("downloading relay descriptors from the "
              + "directory authorities");
        }
      }
    }

    // Write output to disk that only depends on relay descriptors
    if (aw != null) {
      aw.dumpStats();
      aw = null;
    }

    // Prepare sanitized bridge descriptor writer
    SanitizedBridgesWriter sbw = config.getWriteSanitizedBridges() ?
        new SanitizedBridgesWriter(
        new File(config.getSanitizedBridgesWriteDirectory()),
        statsDirectory, config.getReplaceIPAddressesWithHashes(),
        config.getLimitBridgeDescriptorMappings()) : null;

    // Prepare bridge descriptor parser
    BridgeDescriptorParser bdp = config.getWriteSanitizedBridges()
        ? new BridgeDescriptorParser(sbw) : null;

    // Import bridge descriptors
    if (bdp != null && config.getImportBridgeSnapshots()) {
      new BridgeSnapshotReader(bdp,
          new File(config.getBridgeSnapshotsDirectory()),
          statsDirectory);
    }

    // Finish writing sanitized bridge descriptors to disk
    if (sbw != null) {
      sbw.finishWriting();
      sbw = null;
    }

    // Download and process GetTor stats
    if (config.getDownloadGetTorStats()) {
      new GetTorDownloader(config.getGetTorStatsUrl(),
          new File(config.getGetTorDirectory()));
    }

    // Download exit list and store it to disk
    if (config.getDownloadExitList()) {
      new ExitListDownloader();
    }

    // Process bridge pool assignments
    if (config.getProcessBridgePoolAssignments()) {
      new BridgePoolAssignmentsProcessor(
          new File(config.getAssignmentsDirectory()),
          new File(config.getSanitizedAssignmentsDirectory()));
    }

    // Process Torperf files
    if (config.getProcessTorperfFiles()) {
      new TorperfDownloader(new File(config.getTorperfOutputDirectory()),
          config.getTorperfSources(), config.getTorperfFiles());
    }

    // Copy recently published files to a local directory that can then
    // be served via rsync.
    if (config.getProvideFilesViaRsync()) {
      new RsyncDataProvider(
          config.getDirectoryArchivesOutputDirectory() == null ? null :
          new File(config.getDirectoryArchivesOutputDirectory()),
          config.getSanitizedBridgesWriteDirectory() == null ? null :
          new File(config.getSanitizedBridgesWriteDirectory()),
          config.getSanitizedAssignmentsDirectory() == null ? null :
          new File(config.getSanitizedAssignmentsDirectory()),
          config.getDownloadExitList(),
          !config.getDownloadGetTorStats() ? null :
          new File(config.getGetTorDirectory()),
          new File(config.getRsyncDirectory()));
    }

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating ERNIE.");
  }
}
