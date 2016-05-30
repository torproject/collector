/* Copyright 2010--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.exitlists;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.main.LockFile;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.ExitList;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ExitListDownloader extends Thread {

  private static Logger logger =
      Logger.getLogger(ExitListDownloader.class.getName());

  public static void main(Configuration config) throws ConfigurationException {
    logger.info("Starting exit-lists module of CollecTor.");

    // Use lock file to avoid overlapping runs
    LockFile lf = new LockFile(config.getPath(Key.LockFilePath).toString(), "exit-lists");
    lf.acquireLock();

    // Download exit list and store it to disk
    new ExitListDownloader(config).run();

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating exit-lists module of CollecTor.");
  }

  public ExitListDownloader(Configuration config) {}

  public void run() {
    try {
      startProcessing();
    } catch (ConfigurationException ce) {
      logger.severe("Configuration failed: " + ce);
      throw new RuntimeException(ce);
    }
  }

  private void startProcessing() throws ConfigurationException {

    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    Date downloadedDate = new Date();
    String downloadedExitList = null;
    try {
      logger.fine("Downloading exit list...");
      StringBuilder sb = new StringBuilder();
      sb.append("@type tordnsel 1.0\n");
      sb.append("Downloaded " + dateTimeFormat.format(downloadedDate)
          + "\n");
      String exitAddressesUrl =
          "http://exitlist.torproject.org/exit-addresses";
      URL u = new URL(exitAddressesUrl);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      int response = huc.getResponseCode();
      if (response != 200) {
        logger.warning("Could not download exit list. Response code "
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
      logger.fine("Finished downloading exit list.");
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed downloading exit list", e);
      return;
    }
    if (downloadedExitList == null) {
      logger.warning("Failed downloading exit list");
      return;
    }

    SimpleDateFormat tarballFormat =
        new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    tarballFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File("out/exit-lists/" + tarballFormat.format(
        downloadedDate));

    long maxScanMillis = 0L;
    try {
      DescriptorParser descriptorParser =
          DescriptorSourceFactory.createDescriptorParser();
      List<Descriptor> parsedDescriptors =
          descriptorParser.parseDescriptors(downloadedExitList.getBytes(),
          tarballFile.getName());
      if (parsedDescriptors.size() != 1
          || !(parsedDescriptors.get(0) instanceof ExitList)) {
        logger.warning("Could not parse downloaded exit list");
        return;
      }
      ExitList parsedExitList = (ExitList) parsedDescriptors.get(0);
      for (ExitList.Entry entry : parsedExitList.getEntries()) {
        for (long scanMillis : entry.getExitAddresses().values()) {
          maxScanMillis = Math.max(maxScanMillis, scanMillis);
        }
      }
    } catch (DescriptorParseException e) {
      logger.log(Level.WARNING, "Could not parse downloaded exit list",
          e);
    }
    if (maxScanMillis > 0L
        && maxScanMillis + 330L * 60L * 1000L < System.currentTimeMillis()) {
      logger.warning("The last reported scan in the downloaded exit list "
          + "took place at " + dateTimeFormat.format(maxScanMillis)
          + ", which is more than 5:30 hours in the past.");
    }

    /* Write to disk. */
    File rsyncFile = new File("recent/exit-lists/"
        + tarballFile.getName());
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    for (File outputFile : outputFiles) {
      try {
        outputFile.getParentFile().mkdirs();
        BufferedWriter bw = new BufferedWriter(new FileWriter(
            outputFile));
        bw.write(downloadedExitList);
        bw.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Could not write downloaded exit list "
            + "to " + outputFile.getAbsolutePath(), e);
      }
    }

    /* Write stats. */
    StringBuilder dumpStats = new StringBuilder("Finished downloading "
        + "exit list.\nLast three exit lists are:");
    Stack<File> filesInInputDir = new Stack<File>();
    filesInInputDir.add(new File("out/exit-lists"));
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

  /* Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<File>();
    allFiles.add(new File("recent/exit-lists"));
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

