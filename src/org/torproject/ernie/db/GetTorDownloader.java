/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GetTorDownloader {

  public GetTorDownloader(String gettorStatsUrl, File getTorDirectory) {

    Logger logger = Logger.getLogger(GetTorDownloader.class.getName());

    File getTorFile = new File(getTorDirectory, "gettor_stats.txt");
    SortedMap<String, String> getTorStats = new TreeMap<String, String>();

    if (getTorFile.exists() && !getTorFile.isDirectory()) {
      try {
        logger.fine("Reading local gettor_stats.txt file...");
        BufferedReader br = new BufferedReader(new FileReader(
            getTorFile));
        String line = null;
        while ((line = br.readLine()) != null) {
          String date = line.split(" ")[0];
          getTorStats.put(date, line);
        }
        br.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Failed parsing local GetTor stats!",
            e);
        return;
      }
    }

    String unparsed = null;
    try {
      logger.fine("Downloading GetTor stats...");
      URL u = new URL(gettorStatsUrl);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      int response = huc.getResponseCode();
      if (response == 200) {
        BufferedInputStream in = new BufferedInputStream(
            huc.getInputStream());
        StringBuilder sb = new StringBuilder();
        int len;
        byte[] data = new byte[1024];
        while ((len = in.read(data, 0, 1024)) >= 0) {
          sb.append(new String(data, 0, len));
        }
        in.close();
        unparsed = sb.toString();
      }
      logger.fine("Finished downloading GetTor stats.");
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed downloading GetTor stats", e);
      return;
    }

    try {
      logger.fine("Parsing downloaded GetTor stats...");
      BufferedReader br = new BufferedReader(new StringReader(unparsed));
      String line = null;
      while ((line = br.readLine()) != null) {
        String date = line.split(" ")[0];
        getTorStats.put(date, line);
      }
      br.close();
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed parsing downloaded GetTor stats!",
          e);
      return;
    }

    try {
      logger.fine("Writing GetTor stats to local gettor_stats.txt "
          + "file...");
      if (!getTorDirectory.exists()) {
        getTorDirectory.mkdirs();
      }
      BufferedWriter bw = new BufferedWriter(new FileWriter(getTorFile));
      for (String line : getTorStats.values()) {
        bw.write(line + "\n");
      }
      bw.close();
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed writing GetTor stats to local "
          + "gettor_stats.txt file", e);
      return;
    }

    logger.info("Finished downloading and processing statistics on Tor "
        + "packages delivered by GetTor.\nDownloaded " + unparsed.length()
        + " bytes. Last date in statistics is " + getTorStats.lastKey()
        + ".");
  }
}

