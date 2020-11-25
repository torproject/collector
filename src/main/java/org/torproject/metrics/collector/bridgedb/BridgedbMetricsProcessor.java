/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedb;

import org.torproject.descriptor.BridgedbMetrics;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.UnparseableDescriptor;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.persist.BridgedbMetricsPersistence;
import org.torproject.metrics.collector.persist.PersistenceUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.SortedSet;
import java.util.TreeSet;

public class BridgedbMetricsProcessor extends CollecTorMain {

  /**
   * Class logger.
   */
  private static final Logger logger = LoggerFactory.getLogger(
      BridgedbMetricsProcessor.class);

  /**
   * Directory for reading BridgeDB statistics files.
   */
  private File inputDirectory;

  /**
   * File containing file names of previously parsed BridgeDB metrics files.
   */
  private Path parsedBridgedbMetricsFile;

  /**
   * Directory for writing BridgeDB statistics files to be archived in tarballs.
   */
  private String outputPathName;

  /**
   * Directory for writing recently processed BridgeDB statistics files.
   */
  private String recentPathName;

  /**
   * Initialize this class with the given configuration.
   */
  public BridgedbMetricsProcessor(Configuration config) {
    super(config);
  }

  /**
   * Return the module identifier.
   *
   * @return Module identifier.
   */
  @Override
  public String module() {
    return "BridgedbMetrics";
  }

  /**
   * Return the synchronization marker.
   *
   * @return Synchronization marker.
   */
  @Override
  protected String syncMarker() {
    return "BridgedbMetrics";
  }

  /**
   * Start processing files, which includes reading BridgeDB statistics files
   * from disk, possibly decompressing them and splitting them by date, and
   * writing them back to disk.
   *
   * @throws ConfigurationException Thrown if configuration values cannot be
   *     obtained.
   */
  @Override
  protected void startProcessing() throws ConfigurationException {
    logger.info("Starting BridgeDB statistics module of CollecTor.");
    this.initializeConfiguration();
    SortedSet<Path> previouslyProcessedFiles = this.readProcessedFiles(
        this.parsedBridgedbMetricsFile);
    SortedSet<Path> processedFiles = new TreeSet<>();
    logger.info("Reading BridgeDB statistics files in {}.",
        this.inputDirectory);
    for (Descriptor descriptor
        : DescriptorSourceFactory.createDescriptorReader()
        .readDescriptors(this.inputDirectory)) {
      processedFiles.add(descriptor.getDescriptorFile().toPath());
      if (previouslyProcessedFiles.contains(
          descriptor.getDescriptorFile().toPath())) {
        continue;
      }
      if (descriptor instanceof BridgedbMetrics) {
        BridgedbMetrics bridgedbMetrics = (BridgedbMetrics) descriptor;
        BridgedbMetricsPersistence persistence
            = new BridgedbMetricsPersistence(bridgedbMetrics);
        Path tarballPath = Paths.get(this.outputPathName,
            persistence.getStoragePath());
        Path rsyncPath = Paths.get(this.recentPathName,
            persistence.getRecentPath());
        this.writeDescriptor(bridgedbMetrics.getRawDescriptorBytes(),
            tarballPath, rsyncPath);
      } else if (descriptor instanceof UnparseableDescriptor) {
        logger.warn("Skipping unparseable descriptor in file {}.",
            descriptor.getDescriptorFile(),
            ((UnparseableDescriptor) descriptor).getDescriptorParseException());
      } else {
        logger.warn("Skipping unexpected descriptor of type {} in file {}.",
            descriptor.getClass(), descriptor.getDescriptorFile());
      }
    }
    logger.info("Cleaning up directories {} and {}.",
        this.recentPathName, this.outputPathName);
    this.writeProcessedFiles(this.parsedBridgedbMetricsFile, processedFiles);
    this.cleanUpDirectories();
    logger.info("Finished processing BridgeDB statistics file(s).");
  }

  /**
   * Initialize configuration by obtaining current configuration values and
   * storing them in instance attributes.
   */
  private void initializeConfiguration() throws ConfigurationException {
    this.parsedBridgedbMetricsFile = this.config.getPath(Key.StatsPath)
        .resolve("processed-bridgedb-metrics");
    this.outputPathName = config.getPath(Key.OutputPath).toString();
    this.recentPathName = config.getPath(Key.RecentPath).toString();
    this.inputDirectory =
        config.getPath(Key.BridgedbMetricsLocalOrigins).toFile();
  }

  /**
   * Write the given raw descriptor bytes to the given files, and stop at the
   * first file that already exists.
   *
   * @param rawDescriptorBytes Raw descriptor bytes to write.
   * @param outputPaths One or more paths to write to.
   */
  private void writeDescriptor(byte[] rawDescriptorBytes,
      Path ... outputPaths) {
    for (Path outputPath : outputPaths) {
      try {
        File outputFile = outputPath.toFile();
        if (outputFile.exists()) {
          continue;
        }
        if (!outputFile.getParentFile().exists()
            && !outputFile.getParentFile().mkdirs()) {
          logger.warn("Could not create parent directories of {}.", outputFile);
          return;
        }
        Files.write(outputPath, rawDescriptorBytes);
      } catch (IOException e) {
        logger.warn("Unable to write descriptor to file {}.", outputPath, e);
      }
    }
  }

  /**
   * Delete all files from the rsync (out) directory that have not been modified
   * in the last three days (seven weeks).
   */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(Paths.get(this.recentPathName),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(Paths.get(this.outputPathName),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}
