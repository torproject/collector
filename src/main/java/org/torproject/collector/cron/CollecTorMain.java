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
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class CollecTorMain implements Observer, Runnable {

  private static Logger log = LoggerFactory.getLogger(CollecTorMain.class);

  private static final long LIMIT_MB = 200;

  private final AtomicBoolean newConfigAvailable = new AtomicBoolean(false);

  protected Configuration config = new Configuration();

  private Configuration newConfig;

  public CollecTorMain(Configuration conf) {
    this.config.putAll(conf.getPropertiesCopy());
    conf.addObserver(this);
  }

  /**
   * Log all errors preventing successful completion of the module.
   */
  @Override
  public final void run() {
    synchronized (this) {
      if (newConfigAvailable.get()) {
        log.info("Module {} received new configuration.", module());
        synchronized (newConfig) {
          config.clear();
          config.putAll(newConfig.getPropertiesCopy());
          newConfigAvailable.set(false);
        }
      }
    }
    log.info("Starting {} module of CollecTor.", module());
    try {
      startProcessing();
    } catch (Throwable th) { // Catching all to prevent #19771
      log.error("The {} module failed: {}", module(), th.getMessage(), th);
    }
    log.info("Terminating {} module of CollecTor.", module());
  }

  @Override
  public synchronized void update(Observable obs, Object obj) {
    newConfigAvailable.set(true);
    if (obs instanceof Configuration) {
      newConfig = (Configuration) obs;
    }
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
      long megaBytes = (long) (Files.getFileStore(location.toFile()
          .getAbsoluteFile().toPath().getRoot()).getUsableSpace()
              / 1024 / 1024);
      if (megaBytes < LIMIT_MB) {
        log.warn("Available storage critical for {}; only {} MiB left.",
            location, megaBytes);
      } else {
        log.trace("Available storage for {}: {} MiB", location, megaBytes);
      }
    } catch (IOException ioe) {
      throw new RuntimeException("Cannot access " + location + " reason: "
          + ioe.getMessage(), ioe);
    }
  }
}

