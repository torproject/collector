/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.snowflake;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.SnowflakeStats;
import org.torproject.metrics.collector.conf.Annotation;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.downloader.Downloader;
import org.torproject.metrics.collector.persist.PersistenceUtils;
import org.torproject.metrics.collector.persist.SnowflakeStatsPersistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.SortedSet;
import java.util.TreeSet;

public class SnowflakeStatsDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      SnowflakeStatsDownloader.class);

  private String recentPathName;

  private String outputPathName;

  /** Instantiate the snowflake-stats module using the given configuration. */
  public SnowflakeStatsDownloader(Configuration config) {
    super(config);
    this.mapPathDescriptors.put("recent/snowflakes", SnowflakeStats.class);
  }

  @Override
  public String module() {
    return "SnowflakeStats";
  }

  @Override
  protected String syncMarker() {
    return "SnowflakeStats";
  }

  @Override
  protected void startProcessing() throws ConfigurationException {

    this.recentPathName = config.getPath(Key.RecentPath).toString();
    logger.debug("Downloading snowflake stats...");
    URL url = config.getUrl(Key.SnowflakeStatsUrl);
    byte[] downloadedBytes;
    try {
      downloadedBytes = Downloader.downloadFromHttpServer(url);
    } catch (IOException e) {
      logger.warn("Failed downloading {}.", url, e);
      return;
    }
    if (null == downloadedBytes) {
      logger.warn("Could not download {}.", url);
      return;
    }
    logger.debug("Finished downloading {}.", url);

    Path parsedSnowflakeStatsFile = this.config.getPath(Key.StatsPath)
        .resolve("processed-snowflake-stats");
    SortedSet<Path> previouslyProcessedFiles = this.readProcessedFiles(
        parsedSnowflakeStatsFile);
    SortedSet<Path> processedFiles = new TreeSet<>();
    DescriptorParser descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
    SortedSet<LocalDateTime> snowflakeStatsEnds = new TreeSet<>();
    this.outputPathName = config.getPath(Key.OutputPath).toString();
    for (Descriptor descriptor : descriptorParser.parseDescriptors(
        downloadedBytes, null, null)) {
      if (descriptor instanceof SnowflakeStats) {
        SnowflakeStats snowflakeStats = (SnowflakeStats) descriptor;
        LocalDateTime snowflakeStatsEnd = snowflakeStats.snowflakeStatsEnd();
        snowflakeStatsEnds.add(snowflakeStatsEnd);
        SnowflakeStatsPersistence persistence
            = new SnowflakeStatsPersistence(snowflakeStats);
        File tarballFile = new File(outputPathName + "/"
            + persistence.getStoragePath());
        Path relativeFileName = Paths.get(tarballFile.getName());
        processedFiles.add(relativeFileName);
        if (previouslyProcessedFiles.contains(relativeFileName)) {
          continue;
        }
        if (tarballFile.exists()) {
          continue;
        }
        File rsyncFile = new File(this.recentPathName + "/"
            + persistence.getRecentPath());
        File[] outputFiles = new File[] { tarballFile, rsyncFile };
        for (File outputFile : outputFiles) {
          this.writeToFile(outputFile, Annotation.SnowflakeStats.bytes(),
              snowflakeStats.getRawDescriptorBytes());
        }
      }
    }
    if (snowflakeStatsEnds.isEmpty()) {
      logger.warn("Could not parse downloaded snowflake stats.");
      return;
    } else if (snowflakeStatsEnds.last().isBefore(LocalDateTime.now()
        .minusHours(48L))) {
      logger.warn("The latest snowflake stats are older than 48 hours: {}.",
          snowflakeStatsEnds.last());
    }

    this.writeProcessedFiles(parsedSnowflakeStatsFile, processedFiles);
    this.cleanUpDirectories();
  }

  /**
   * Write the given byte array(s) to the given file.
   *
   * <p>If the file already exists, it is overwritten. If the parent directory
   * (or any of its parent directories) does not exist, it is created. If
   * anything goes wrong, log a warning and return.</p>
   *
   * @param outputFile File to write to.
   * @param bytes One or more byte arrays.
   */
  private void writeToFile(File outputFile, byte[] ... bytes) {
    try {
      if (!outputFile.getParentFile().exists()
          && !outputFile.getParentFile().mkdirs()) {
        logger.warn("Could not create parent directories of {}.", outputFile);
        return;
      }
      OutputStream os = new FileOutputStream(outputFile);
      for (byte[] b : bytes) {
        os.write(b);
      }
      os.close();
    } catch (IOException e) {
      logger.warn("Could not write downloaded snowflake stats to {}",
          outputFile.getAbsolutePath(), e);
    }
  }

  /** Delete all files from the rsync (out) directory that have not been
   * modified in the last three days (seven weeks). */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(
        Paths.get(this.recentPathName, "snowflakes"),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(
        Paths.get(this.outputPathName, "snowflakes"),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}

