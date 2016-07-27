/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class CollecTorMain implements Runnable {

  private static Logger log = LoggerFactory.getLogger(CollecTorMain.class);

  private static final long LIMIT_MB = 200;

  protected Configuration config;

  public CollecTorMain(Configuration conf) {
    this.config = conf;
  }

  /**
   * Log errors preventing successful completion of the module.
   */
  @Override
  public final void run() {
    log.info("Starting {} module of CollecTor.", module());
    try {
      startProcessing();
    } catch (ConfigurationException | RuntimeException ce) {
      log.error("The {} module failed: {}", module(), ce.getMessage(), ce);
    }
    log.info("Terminating {} module of CollecTor.", module());
  }

  /**
   * Module specific code goes here.
   */
  protected abstract void startProcessing() throws ConfigurationException;

  /**
   * Returns the module name for logging purposes.
   */
  public abstract String module();

  /**
   * Checks the available space for the storage the given path is located on and
   * logs a warning, if 200 MiB or less are available, and otherwise logs
   * available space in TRACE level.
   */
  public static void checkAvailableSpace(Path location) {
    try {
      long megaBytes = (long) (Files.getFileStore(location).getUsableSpace()
          / 1024 / 1024);
      if (megaBytes < LIMIT_MB) {
        log.warn("Available storage critical for {}; only {} MiB left.",
            location, megaBytes);
      } else {
        log.trace("Available storage for {}: {} MiB", location, megaBytes);
      }
    } catch (IOException ioe) {
      log.warn("Cannot access {}; reason: {}", location, ioe.getMessage(),
          ioe);
    }
  }
}

