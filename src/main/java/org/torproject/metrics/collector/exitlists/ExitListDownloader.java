/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.exitlists;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.ExitList;
import org.torproject.metrics.collector.conf.Annotation;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.downloader.Downloader;
import org.torproject.metrics.collector.persist.PersistenceUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeSet;

public class ExitListDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      ExitListDownloader.class);

  private static final String EXITLISTS = "exit-lists";

  private String outputPathName;

  private String recentPathName;

  /** Instantiate the exit-lists module using the given configuration. */
  public ExitListDownloader(Configuration config) {
    super(config);
    this.mapPathDescriptors.put("recent/exit-lists", ExitList.class);
  }

  @Override
  public String module() {
    return "exitlists";
  }

  @Override
  protected String syncMarker() {
    return "Exitlist";
  }

  @Override
  protected void startProcessing() throws ConfigurationException {

    outputPathName = Paths.get(config.getPath(Key.OutputPath).toString(),
        EXITLISTS).toString();
    recentPathName = Paths.get(config.getPath(Key.RecentPath).toString(),
        EXITLISTS).toString();
    Date downloadedDate = new Date();
    String downloadedExitList;
    logger.debug("Downloading exit list...");
    StringBuilder sb = new StringBuilder();
    sb.append(Annotation.ExitList.toString());
    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    sb.append("Downloaded ").append(dateTimeFormat.format(downloadedDate))
        .append("\n");
    URL url = config.getUrl(Key.ExitlistUrl);
    byte[] downloadedBytes;
    try {
      downloadedBytes = Downloader.downloadFromHttpServer(url);
    } catch (IOException e) {
      logger.warn("Failed downloading exit list", e);
      return;
    }
    if (null != downloadedBytes) {
      sb.append(new String(downloadedBytes));
      downloadedExitList = sb.toString();
      logger.debug("Finished downloading exit list.");
    } else {
      logger.warn("Failed downloading exit list.");
      return;
    }

    SimpleDateFormat tarballFormat =
        new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    File tarballFile = Paths.get(outputPathName,
        tarballFormat.format(downloadedDate)).toFile();

    DescriptorParser descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
    int parsedExitLists = 0;
    int otherDescriptors = 0;
    long maxScanMillis = 0L;
    for (Descriptor descriptor : descriptorParser.parseDescriptors(
        downloadedExitList.getBytes(), null, tarballFile.getName())) {
      if (descriptor instanceof ExitList) {
        parsedExitLists++;
        ExitList parsedExitList = (ExitList) descriptor;
        for (ExitList.Entry entry : parsedExitList.getEntries()) {
          for (long scanMillis : entry.getExitAddresses().values()) {
            maxScanMillis = Math.max(maxScanMillis, scanMillis);
          }
        }
      } else {
        otherDescriptors++;
      }
    }
    if (parsedExitLists != 1 || otherDescriptors > 0) {
      logger.warn("Could not parse downloaded exit list");
      return;
    }
    if (maxScanMillis > 0L
        && maxScanMillis + 330L * 60L * 1000L < System.currentTimeMillis()) {
      logger.warn("The last reported scan in the downloaded exit list took "
          + "place at {}, which is more than 5:30 hours in the past.",
          dateTimeFormat.format(maxScanMillis));
    }

    /* Write to disk. */
    File rsyncFile = new File(recentPathName, tarballFile.getName());
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    for (File outputFile : outputFiles) {
      try {
        outputFile.getParentFile().mkdirs();
        BufferedWriter bw = new BufferedWriter(new FileWriter(
            outputFile));
        bw.write(downloadedExitList);
        bw.close();
      } catch (IOException e) {
        logger.warn("Could not write downloaded exit list to {}",
            outputFile.getAbsolutePath(), e);
      }
    }

    /* Write stats. */
    StringBuilder dumpStats = new StringBuilder("Finished downloading "
        + "exit list.\nLast three exit lists are:");
    Stack<File> filesInInputDir = new Stack<>();
    filesInInputDir.add(new File(outputPathName));
    SortedSet<File> lastThreeExitLists = new TreeSet<>();
    while (!filesInInputDir.isEmpty()) {
      File pop = filesInInputDir.pop();
      if (pop.isDirectory()) {
        SortedSet<File> lastThreeElements
            = new TreeSet<>(Arrays.asList(pop.listFiles()));
        while (lastThreeElements.size() > 3) {
          lastThreeElements.remove(lastThreeElements.first());
        }
        filesInInputDir.addAll(lastThreeElements);
      } else {
        lastThreeExitLists.add(pop);
        while (lastThreeExitLists.size() > 3) {
          lastThreeExitLists.remove(lastThreeExitLists.first());
        }
      }
    }
    for (File f : lastThreeExitLists) {
      dumpStats.append("\n").append(f.getName());
    }
    logger.info(dumpStats.toString());

    this.cleanUpDirectories();
  }

  /** Delete all files from the rsync (out) directory that have not been
   * modified in the last three days (seven weeks). */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(Paths.get(this.recentPathName),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(Paths.get(this.outputPathName),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}

