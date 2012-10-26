/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.exitlists;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ExitListDownloader {
  public ExitListDownloader() {
    Logger logger = Logger.getLogger(ExitListDownloader.class.getName());
    try {
      logger.fine("Downloading exit list...");
      String exitAddressesUrl =
          "http://exitlist.torproject.org/exit-addresses";
      URL u = new URL(exitAddressesUrl);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      int response = huc.getResponseCode();
      if (response != 200) {
        logger.warning("Could not download exit list. Response code " + 
            response);
        return;
      }
      BufferedInputStream in = new BufferedInputStream(
          huc.getInputStream());
      SimpleDateFormat printFormat =
          new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
      printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      Date downloadedDate = new Date();
      File exitListFile = new File("exitlist/" + printFormat.format(
          downloadedDate));
      exitListFile.getParentFile().mkdirs();
      SimpleDateFormat dateTimeFormat =
          new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          exitListFile));
      bw.write("@type tordnsel 1.0\n");
      bw.write("Downloaded " + dateTimeFormat.format(downloadedDate)
          + "\n");
      int len;
      byte[] data = new byte[1024];
      while ((len = in.read(data, 0, 1024)) >= 0) {
        bw.write(new String(data, 0, len));
      }   
      in.close();
      bw.close();
      logger.fine("Finished downloading exit list.");
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed downloading exit list", e);
      return;
    }

    /* Write stats. */
    StringBuilder dumpStats = new StringBuilder("Finished downloading "
        + "exit list.\nLast three exit lists are:");
    Stack<File> filesInInputDir = new Stack<File>();
    filesInInputDir.add(new File("exitlist"));
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
  }
}

