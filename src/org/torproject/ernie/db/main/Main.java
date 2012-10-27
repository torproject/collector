/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.main;

import java.util.ArrayList;
import java.util.List;
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

    // Keep a list of all threads, so that we can join them all before
    // exiting.
    List<Thread> threads = new ArrayList<Thread>();

    // Import/download relay descriptors from the various sources
    if (config.getWriteDirectoryArchives()) {
      threads.add(new ArchiveWriter(config));
    }

    // Sanitize bridge descriptors
    if (config.getImportBridgeSnapshots() &&
        config.getWriteSanitizedBridges()) {
      threads.add(new SanitizedBridgesWriter(config));
    }

    // Download exit list and store it to disk
    if (config.getDownloadExitList()) {
      threads.add(new ExitListDownloader(config));
    }

    // Process bridge pool assignments
    if (config.getProcessBridgePoolAssignments()) {
      threads.add(new BridgePoolAssignmentsProcessor(config));
    }

    // Process Torperf files
    if (config.getProcessTorperfFiles()) {
      threads.add(new TorperfDownloader(config));
    }

    // Run threads
    for (Thread thread : threads) {
      thread.start();
    }
    for (Thread thread : threads) {
      try {
        thread.join();
      } catch (InterruptedException e) {
      }
    }

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating ERNIE.");
  }
}
