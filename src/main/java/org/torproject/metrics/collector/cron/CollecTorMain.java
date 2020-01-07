/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.cron;

import org.torproject.descriptor.Descriptor;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.conf.SourceType;
import org.torproject.metrics.collector.sync.SyncManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;

public abstract class CollecTorMain extends SyncManager
    implements Callable<Object>, Runnable {

  private static final Logger logger = LoggerFactory.getLogger(
      CollecTorMain.class);

  private static final long LIMIT_MB = 200;
  public static final String SOURCES = "Sources";

  protected Configuration config = new Configuration();

  protected final Map<String, Class<? extends Descriptor>> mapPathDescriptors
      = new HashMap<>();

  public CollecTorMain(Configuration conf) {
    this.config.putAll(conf.getPropertiesCopy());
  }

  /**
   * Log all errors preventing successful completion of the module.
   */
  @Override
  public final void run() {
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

  /**
   * Wrapper for {@code run}.
   */
  @Override
  public final Object call() {
    run();
    return null;
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
      long megaBytes = Files.getFileStore(location.toFile()
          .getAbsoluteFile().toPath().getRoot()).getUsableSpace()
              / 1024 / 1024;
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

  /**
   * Read file names of processed files from the given state file.
   *
   * @param stateFile State file to read file names from.
   * @return File names of processed files.
   */
  public SortedSet<Path> readProcessedFiles(Path stateFile) {
    SortedSet<Path> processedFiles = new TreeSet<>();
    if (Files.exists(stateFile)) {
      try {
        for (String line : Files.readAllLines(stateFile)) {
          processedFiles.add(Paths.get(line));
        }
      } catch (IOException e) {
        logger.warn("I/O error while reading processed files.", e);
      }
    }
    return processedFiles;
  }

  /**
   * Write file names of processed files to the state file.
   *
   * @param stateFile State file to write file names to.
   * @param processedFiles File names of processed files.
   */
  public void writeProcessedFiles(Path stateFile,
      SortedSet<Path> processedFiles) {
    List<String> lines = new ArrayList<>();
    for (Path processedFile : processedFiles) {
      lines.add(processedFile.toString());
    }
    try {
      if (!Files.exists(stateFile)) {
        Files.createDirectories(stateFile.getParent());
      }
      Files.write(stateFile, lines);
    } catch (IOException e) {
      logger.warn("I/O error while writing processed files.", e);
    }
  }
}

