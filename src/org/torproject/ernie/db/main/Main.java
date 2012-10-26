/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.main;

import java.io.File;
import java.util.logging.Logger;

import org.torproject.ernie.db.bridgedescs.SanitizedBridgesWriter;
import org.torproject.ernie.db.bridgepools.BridgePoolAssignmentsProcessor;
import org.torproject.ernie.db.exitlists.ExitListDownloader;
import org.torproject.ernie.db.relaydescs.ArchiveWriter;
import org.torproject.ernie.db.torperf.TorperfDownloader;

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

    // Import/download relay descriptors from the various sources
    if (config.getWriteDirectoryArchives()) {
      new ArchiveWriter(config, statsDirectory);
    }

    // Sanitize bridge descriptors
    if (config.getImportBridgeSnapshots() &&
        config.getWriteSanitizedBridges()) {
      new SanitizedBridgesWriter(config, statsDirectory);
    }

    // Download exit list and store it to disk
    if (config.getDownloadExitList()) {
      new ExitListDownloader();
    }

    // Process bridge pool assignments
    if (config.getProcessBridgePoolAssignments()) {
      new BridgePoolAssignmentsProcessor(config);
    }

    // Process Torperf files
    if (config.getProcessTorperfFiles()) {
      new TorperfDownloader(config);
    }

    // Copy recently published files to a local directory that can then
    // be served via rsync.
    if (config.getProvideFilesViaRsync()) {
      new RsyncDataProvider(
          !config.getWriteDirectoryArchives() ? null :
          new File(config.getDirectoryArchivesOutputDirectory()),
          !config.getWriteSanitizedBridges() ? null :
          new File(config.getSanitizedBridgesWriteDirectory()),
          !config.getProcessBridgePoolAssignments() ? null :
          new File(config.getSanitizedAssignmentsDirectory()),
          config.getDownloadExitList(),
          !config.getProcessTorperfFiles() ? null :
          new File(config.getTorperfOutputDirectory()),
          new File(config.getRsyncDirectory()));
    }

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating ERNIE.");
  }
}
