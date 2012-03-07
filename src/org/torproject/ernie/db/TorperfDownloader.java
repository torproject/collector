/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;

/* Download possibly truncated Torperf .data and .extradata files from
 * configured sources and append them to the files we already have. */
public class TorperfDownloader {

  private File torperfOutputDirectory = null;
  private SortedMap<String, String> torperfSources = null;
  private SortedMap<String, List<String>> torperfDataFiles = null;
  private SortedMap<String, List<String>> torperfExtradataFiles = null;
  private Logger logger = null;

  public TorperfDownloader(File torperfOutputDirectory,
      SortedMap<String, String> torperfSources,
      SortedMap<String, List<String>> torperfDataFiles,
      SortedMap<String, List<String>> torperfExtradataFiles) {
    if (torperfOutputDirectory == null) {
      throw new IllegalArgumentException();
    }
    this.torperfOutputDirectory = torperfOutputDirectory;
    this.torperfSources = torperfSources;
    this.torperfDataFiles = torperfDataFiles;
    this.torperfExtradataFiles = torperfExtradataFiles;
    if (!this.torperfOutputDirectory.exists()) {
      this.torperfOutputDirectory.mkdirs();
    }
    this.logger = Logger.getLogger(TorperfDownloader.class.getName());
    this.downloadAndMergeFiles(this.torperfDataFiles, true);
    this.downloadAndMergeFiles(this.torperfExtradataFiles, false);
  }

  private void downloadAndMergeFiles(
      SortedMap<String, List<String>> dataOrExtradataFiles,
      boolean isDataFile) {
    for (Map.Entry<String, List<String>> e :
        dataOrExtradataFiles.entrySet()) {
      String sourceName = e.getKey();
      String sourceBaseUrl = torperfSources.get(sourceName);
      List<String> files = e.getValue();
      for (String file : files) {
        String url = sourceBaseUrl + file;
        File outputFile = new File(torperfOutputDirectory,
            sourceName + "-" + file);
        this.downloadAndMergeFile(url, outputFile, isDataFile);
      }
    }
  }

  private void downloadAndMergeFile(String url, File outputFile,
      boolean isDataFile) {
    String lastTimestampLine = null;
    int linesAfterLastTimestampLine = 0;
    if (outputFile.exists() && outputFile.lastModified() >
        System.currentTimeMillis() - 330L * 60L * 1000L) {
      return;
    } else if (outputFile.exists()) {
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            outputFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (isDataFile || line.contains(" LAUNCH")) {
            lastTimestampLine = line;
            linesAfterLastTimestampLine = 0;
          } else {
            linesAfterLastTimestampLine++;
          }
        }
        br.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Failed reading '"
            + outputFile.getAbsolutePath() + "' to find the last line to "
            + "append to.", e);
        return;
      }
    }
    try {
      this.logger.fine("Downloading " + (isDataFile ? ".data" :
          ".extradata") + " file from '" + url + "' and merging it into "
          + "'" + outputFile.getAbsolutePath() + "'.");
      URL u = new URL(url);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      BufferedReader br = new BufferedReader(new InputStreamReader(
          huc.getInputStream()));
      String line;
      BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile,
          true));
      boolean copyLines = lastTimestampLine == null;
      while ((line = br.readLine()) != null) {
        if (copyLines && linesAfterLastTimestampLine == 0) {
          if (isDataFile || line.contains(" LAUNCH")) {
            lastTimestampLine = line;
          }
          bw.write(line + "\n");
        } else if (copyLines && linesAfterLastTimestampLine > 0) {
          linesAfterLastTimestampLine--;
        } else if (line.equals(lastTimestampLine)) {
          copyLines = true;
        }
      }
      bw.close();
      br.close();
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed downloading and merging '" + url
          + "'.", e);
      return;
    }
    if (lastTimestampLine == null) {
      logger.warning("'" + outputFile.getAbsolutePath() + "' doesn't "
          + "contain any timestamp lines.  Unable to check whether that "
          + "file is stale or not.");
    } else {
      long lastTimestampMillis = -1L;
      if (isDataFile) {
        lastTimestampMillis = Long.parseLong(lastTimestampLine.substring(
            0, lastTimestampLine.indexOf(" "))) * 1000L;
      } else {
        lastTimestampMillis = Long.parseLong(lastTimestampLine.substring(
            lastTimestampLine.indexOf(" LAUNCH=") + " LAUNCH=".length(),
            lastTimestampLine.indexOf(".",
            lastTimestampLine.indexOf(" LAUNCH=")))) * 1000L;
      }
      if (lastTimestampMillis < System.currentTimeMillis()
          - 330L * 60L * 1000L) {
        logger.warning("The last timestamp in '"
            + outputFile.getAbsolutePath() + "' is more than 5:30 hours "
            + "old: " + lastTimestampMillis);
      }
    }
  }
}

