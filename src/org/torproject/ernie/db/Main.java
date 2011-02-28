/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.util.*;
import java.util.logging.*;

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

    // Prepare bridge stats file handler
    BridgeStatsFileHandler bsfh = config.getWriteBridgeStats() ?
        new BridgeStatsFileHandler(
        config.getWriteAggregateStatsDatabase() ?
        config.getRelayDescriptorDatabaseJDBC() : null) : null;

    // Prepare writing relay descriptor archive to disk
    ArchiveWriter aw = config.getWriteDirectoryArchives() ?
        new ArchiveWriter(
        new File(config.getDirectoryArchivesOutputDirectory())) : null;

    // Prepare writing relay descriptors to database
    RelayDescriptorDatabaseImporter rddi =
        config.getWriteRelayDescriptorDatabase() ||
        config.getWriteRelayDescriptorsRawFiles() ?
        new RelayDescriptorDatabaseImporter(
        config.getWriteRelayDescriptorDatabase() ?
        config.getRelayDescriptorDatabaseJDBC() : null,
        config.getWriteRelayDescriptorsRawFiles() ?
        config.getRelayDescriptorRawFilesDirectory() : null) : null;

    // Prepare relay descriptor parser (only if we are writing stats or
    // directory archives to disk)
    RelayDescriptorParser rdp = config.getWriteBridgeStats() ||
        config.getWriteDirectoryArchives() ||
        config.getWriteRelayDescriptorDatabase() ||
        config.getWriteRelayDescriptorsRawFiles() ?
        new RelayDescriptorParser(bsfh, aw, rddi) : null;

    // Import/download relay descriptors from the various sources
    if (rdp != null) {
      RelayDescriptorDownloader rdd = null;
      if (config.getDownloadRelayDescriptors()) {
        List<String> dirSources =
            config.getDownloadFromDirectoryAuthorities();
        boolean downloadCurrentConsensus = aw != null || bsfh != null ||
            rddi != null;
        boolean downloadCurrentVotes = aw != null;
        boolean downloadAllServerDescriptors = aw != null ||
            rddi != null;
        boolean downloadAllExtraInfos = aw != null || rddi != null;
        rdd = new RelayDescriptorDownloader(rdp, dirSources,
            downloadCurrentConsensus, downloadCurrentVotes,
            downloadAllServerDescriptors, downloadAllExtraInfos);
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
        rdd.downloadMissingDescriptors();
        rdd.writeFile();
        rdd = null;
        if (aw != null) {
          aw.intermediateStats("downloading relay descriptors from the "
              + "directory authorities");
        }
      }
    }

    // Close database connection (if active)
    if (rddi != null)   {
      rddi.closeConnection();
    }

    // Write output to disk that only depends on relay descriptors
    if (aw != null) {
      aw.dumpStats();
      aw = null;
    }

    // Prepare consensus stats file handler
    ConsensusStatsFileHandler csfh = config.getWriteConsensusStats() ?
        new ConsensusStatsFileHandler(
        config.getWriteAggregateStatsDatabase() ?
        config.getRelayDescriptorDatabaseJDBC() : null) : null;

    // Prepare sanitized bridge descriptor writer
    SanitizedBridgesWriter sbw = config.getWriteSanitizedBridges() ?
        new SanitizedBridgesWriter(
        new File(config.getSanitizedBridgesWriteDirectory()),
        statsDirectory, config.getReplaceIPAddressesWithHashes(),
        config.getLimitBridgeDescriptorMappings()) : null;

    // Prepare bridge descriptor parser
    BridgeDescriptorParser bdp = config.getWriteConsensusStats() ||
        config.getWriteBridgeStats() || config.getWriteSanitizedBridges()
        ? new BridgeDescriptorParser(csfh, bsfh, sbw) : null;

    // Import bridge descriptors
    if (bdp != null && config.getImportSanitizedBridges()) {
      new SanitizedBridgesReader(bdp,
          new File(config.getSanitizedBridgesDirectory()),
          statsDirectory, config.getKeepSanitizedBridgesImportHistory());
    }
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

    // Write updated stats files to disk
    if (bsfh != null) {
      bsfh.writeFiles();
      bsfh = null;
    }
    if (csfh != null) {
      csfh.writeFiles();
      csfh = null;
    }

    // Import and process torperf stats
    if (config.getImportWriteTorperfStats()) {
      new TorperfProcessor(new File(config.getTorperfDirectory()),
          statsDirectory,
          config.getWriteAggregateStatsDatabase() ?
          config.getRelayDescriptorDatabaseJDBC() : null);
    }

    // Download and process GetTor stats
    if (config.getDownloadProcessGetTorStats()) {
      new GetTorProcessor(config.getGetTorStatsUrl(),
          config.getWriteAggregateStatsDatabase() ?
          config.getRelayDescriptorDatabaseJDBC() : null);
    }

    // Download exit list and store it to disk
    if (config.getDownloadExitList()) {
      new ExitListDownloader();
    }

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating ERNIE.");
  }
}
