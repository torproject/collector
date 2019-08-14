/* Copyright 2019 The Tor Project
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
import org.torproject.metrics.collector.persist.SnowflakeStatsPersistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeSet;

public class SnowflakeStatsDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      SnowflakeStatsDownloader.class);

  private String recentPathName;

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
    ByteArrayOutputStream downloadedSnowflakeStats
        = this.downloadFromHttpServer(url);
    if (null == downloadedSnowflakeStats) {
      return;
    }
    logger.debug("Finished downloading {}.", url);

    DescriptorParser descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
    SortedSet<LocalDateTime> snowflakeStatsEnds = new TreeSet<>();
    String outputPathName = config.getPath(Key.OutputPath).toString();
    for (Descriptor descriptor : descriptorParser.parseDescriptors(
        downloadedSnowflakeStats.toByteArray(), null, null)) {
      if (descriptor instanceof SnowflakeStats) {
        SnowflakeStats snowflakeStats = (SnowflakeStats) descriptor;
        LocalDateTime snowflakeStatsEnd = snowflakeStats.snowflakeStatsEnd();
        snowflakeStatsEnds.add(snowflakeStatsEnd);
        SnowflakeStatsPersistence persistence
            = new SnowflakeStatsPersistence(snowflakeStats);
        File tarballFile = new File(outputPathName + "/"
            + persistence.getStoragePath());
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

    this.cleanUpRsyncDirectory();
  }

  /**
   * Download the given URL from an HTTP server and return a stream with
   * downloaded bytes.
   *
   * <p>If anything goes wrong while downloading, log a warning and return
   * {@code null}.</p>
   *
   * @param url URL to download.
   * @return Stream with downloaded bytes, or {@code null} if an error has
   *     occurred.
   */
  private ByteArrayOutputStream downloadFromHttpServer(URL url) {
    ByteArrayOutputStream downloadedBytes = new ByteArrayOutputStream();
    try  {
      HttpURLConnection huc = (HttpURLConnection) url.openConnection();
      huc.setRequestMethod("GET");
      huc.setReadTimeout(5000);
      huc.connect();
      int response = huc.getResponseCode();
      if (response != 200) {
        logger.warn("Could not download {}. Response code {}", url, response);
        return null;
      }
      try (BufferedInputStream in = new BufferedInputStream(
          huc.getInputStream())) {
        int len;
        byte[] data = new byte[1024];
        while ((len = in.read(data, 0, 1024)) >= 0) {
          downloadedBytes.write(data, 0, len);
        }
      }
    } catch (IOException e) {
      logger.warn("Failed downloading {}.", url, e);
      return null;
    }
    return downloadedBytes;
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

  /** Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<>();
    allFiles.add(new File(recentPathName));
    while (!allFiles.isEmpty()) {
      File file = allFiles.pop();
      if (file.isDirectory()) {
        allFiles.addAll(Arrays.asList(file.listFiles()));
      } else if (file.lastModified() < cutOffMillis) {
        file.delete();
      }
    }
  }
}

