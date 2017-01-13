/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.conf.SourceType;
import org.torproject.collector.sync.SyncManager;
import org.torproject.descriptor.Descriptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

public abstract class CollecTorMain extends SyncManager
    implements Callable<Object>, Observer, Runnable {

  private static final Logger logger = LoggerFactory.getLogger(
      CollecTorMain.class);

  private static final long LIMIT_MB = 200;
  public static final String SOURCES = "Sources";
  private final AtomicBoolean newConfigAvailable = new AtomicBoolean(false);

  protected Configuration config = new Configuration();

  private Configuration newConfig;

  protected final Map<String, Class<? extends Descriptor>> mapPathDescriptors
      = new HashMap<>();

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
        logger.info("Module {} is using the new configuration.", module());
        synchronized (newConfig) {
          config.clear();
          config.putAll(newConfig.getPropertiesCopy());
          newConfigAvailable.set(false);
        }
      }
    }
    try {
      if (!isSyncOnly()) {
        logger.info("Starting {} module of CollecTor.", module());
        startProcessing();
        logger.info("Terminating {} module of CollecTor.", module());
      }
    } catch (Throwable th) { // Catching all to prevent #19771
      logger.error("The {} module failed: {}", module(), th.getMessage(), th);
    }
    try {
      if (isSync()) {
        logger.info("Starting sync-run of module {} of CollecTor.", module());
        this.merge(this.config, this.syncMarker(),
            this.syncMapPathsDescriptors());
        logger.info("Finished sync-run of module {} of CollecTor.", module());
      }
    } catch (Throwable th) { // Catching all (cf. above).
      logger.error("Sync-run of {} module failed: {}", module(),
          th.getMessage(), th);
    }
  }

  private boolean isSync() throws ConfigurationException {
    String key = this.syncMarker() + SOURCES;
    return Key.has(key) && config.getSourceTypeSet(Key.valueOf(key))
        .contains(SourceType.Sync);
  }

  private boolean isSyncOnly() throws ConfigurationException {
    String key = this.syncMarker() + SOURCES;
    return this.isSync()
        && config.getSourceTypeSet(Key.valueOf(key)).size() == 1;
  }

  /** Wrapper for <code>run</code>. */
  @Override
  public final Object call() {
    run();
    return null;
  }

  @Override
  public synchronized void update(Observable obs, Object obj) {
    newConfigAvailable.set(true);
    if (obs instanceof Configuration) {
      newConfig = (Configuration) obs;
      logger.info("Module {} just received a new configuration.", module());
    }
  }

  /**
   * Module specific code goes here.
   */
  protected abstract void startProcessing() throws ConfigurationException;

  /**
   * Returns property prefix/infix/postfix for Sync related properties.
   */
  protected abstract String syncMarker();

  /**
   * Returns the module name for logging purposes.
   */
  public abstract String module();

  /** Returns map of path and descriptor type for download. */
  public Map<String, Class<? extends Descriptor>> syncMapPathsDescriptors() {
    return Collections.unmodifiableMap(mapPathDescriptors);
  }

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
        logger.warn("Available storage critical for {}; only {} MiB left.",
            location, megaBytes);
      } else {
        logger.trace("Available storage for {}: {} MiB", location, megaBytes);
      }
    } catch (IOException ioe) {
      throw new RuntimeException("Cannot access " + location + " reason: "
          + ioe.getMessage(), ioe);
    }
  }
}

