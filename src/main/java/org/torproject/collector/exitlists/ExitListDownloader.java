/* Copyright 2010--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.exitlists;

import org.torproject.collector.conf.Annotation;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.cron.CollecTorMain;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.ExitList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;

public class ExitListDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      ExitListDownloader.class);

  private static final String EXITLISTS = "exit-lists";

  private String outputPathName;

  private String recentPathName;

  /** Instanciate the exit-lists module using the given configuration. */
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

    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    outputPathName = Paths.get(config.getPath(Key.OutputPath).toString(),
        EXITLISTS).toString();
    recentPathName = Paths.get(config.getPath(Key.RecentPath).toString(),
        EXITLISTS).toString();
    Date downloadedDate = new Date();
    String downloadedExitList = null;
    try {
      logger.debug("Downloading exit list...");
      StringBuilder sb = new StringBuilder();
      sb.append(Annotation.Torperf.toString());
      sb.append("Downloaded " + dateTimeFormat.format(downloadedDate)
          + "\n");
      URL url = config.getUrl(Key.ExitlistUrl);
      HttpURLConnection huc = (HttpURLConnection) url.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      int response = huc.getResponseCode();
      if (response != 200) {
        logger.warn("Could not download exit list. Response code "
            + response);
        return;
      }
      BufferedInputStream in = new BufferedInputStream(
          huc.getInputStream());
      int len;
      byte[] data = new byte[1024];
      while ((len = in.read(data, 0, 1024)) >= 0) {
        sb.append(new String(data, 0, len));
      }
      in.close();
      downloadedExitList = sb.toString();
      logger.debug("Finished downloading exit list.");
    } catch (IOException e) {
      logger.warn("Failed downloading exit list", e);
      return;
    }
    if (downloadedExitList == null) {
      logger.warn("Failed downloading exit list.");
      return;
    }

    SimpleDateFormat tarballFormat =
        new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    tarballFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = Paths.get(outputPathName,
        tarballFormat.format(downloadedDate)).toFile();

    long maxScanMillis = 0L;
    try {
      DescriptorParser descriptorParser =
          DescriptorSourceFactory.createDescriptorParser();
      List<Descriptor> parsedDescriptors =
          descriptorParser.parseDescriptors(downloadedExitList.getBytes(),
          tarballFile.getName());
      if (parsedDescriptors.size() != 1
          || !(parsedDescriptors.get(0) instanceof ExitList)) {
        logger.warn("Could not parse downloaded exit list");
        return;
      }
      ExitList parsedExitList = (ExitList) parsedDescriptors.get(0);
      for (ExitList.Entry entry : parsedExitList.getEntries()) {
        for (long scanMillis : entry.getExitAddresses().values()) {
          maxScanMillis = Math.max(maxScanMillis, scanMillis);
        }
      }
    } catch (DescriptorParseException e) {
      logger.warn("Could not parse downloaded exit list",
          e);
    }
    if (maxScanMillis > 0L
        && maxScanMillis + 330L * 60L * 1000L < System.currentTimeMillis()) {
      logger.warn("The last reported scan in the downloaded exit list "
          + "took place at " + dateTimeFormat.format(maxScanMillis)
          + ", which is more than 5:30 hours in the past.");
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
        logger.warn("Could not write downloaded exit list "
            + "to " + outputFile.getAbsolutePath(), e);
      }
    }

    /* Write stats. */
    StringBuilder dumpStats = new StringBuilder("Finished downloading "
        + "exit list.\nLast three exit lists are:");
    Stack<File> filesInInputDir = new Stack<File>();
    filesInInputDir.add(new File(outputPathName));
    SortedSet<File> lastThreeExitLists = new TreeSet<File>();
    while (!filesInInputDir.isEmpty()) {
      File pop = filesInInputDir.pop();
      if (pop.isDirectory()) {
        SortedSet<File> lastThreeElements = new TreeSet<File>();
        for (File f : pop.listFiles()) {
          lastThreeElements.add(f);
        }
        while (lastThreeElements.size() > 3) {
          lastThreeElements.remove(lastThreeElements.first());
        }
        for (File f : lastThreeElements) {
          filesInInputDir.add(f);
        }
      } else {
        lastThreeExitLists.add(pop);
        while (lastThreeExitLists.size() > 3) {
          lastThreeExitLists.remove(lastThreeExitLists.first());
        }
      }
    }
    for (File f : lastThreeExitLists) {
      dumpStats.append("\n" + f.getName());
    }
    logger.info(dumpStats.toString());

    this.cleanUpRsyncDirectory();
  }

  /** Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() throws ConfigurationException {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<File>();
    allFiles.add(new File(recentPathName, EXITLISTS));
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

