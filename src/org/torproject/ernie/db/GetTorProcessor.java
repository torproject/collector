/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.net.*;
import java.sql.*;
import java.util.*;
import java.util.logging.*;

public class GetTorProcessor {
  public GetTorProcessor(String gettorStatsUrl, String connectionURL) {
    Logger logger = Logger.getLogger(GetTorProcessor.class.getName());
    String unparsed = null;
    try {
      logger.fine("Downloading gettor stats...");
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
      logger.fine("Finished downloading gettor stats.");
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed downloading gettor stats", e);
      return;
    }

    SortedSet<String> columns = new TreeSet<String>();
    SortedMap<String, Map<String, Integer>> data =
        new TreeMap<String, Map<String, Integer>>();
    try {
      logger.fine("Parsing downloaded gettor stats...");
      BufferedReader br = new BufferedReader(new StringReader(unparsed));
      String line = null;
      while ((line = br.readLine()) != null) {
        String[] parts = line.split(" ");
        String date = parts[0];
        Map<String, Integer> obs = new HashMap<String, Integer>();
        data.put(date, obs);
        for (int i = 2; i < parts.length; i++) {
          String key = parts[i].split(":")[0].toLowerCase();
          Integer value = new Integer(parts[i].split(":")[1]);
          columns.add(key);
          obs.put(key, value);
        }
      }
      br.close();
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed parsing gettor stats!", e);
      return;
    } catch (NumberFormatException e) {
      logger.log(Level.WARNING, "Failed parsing gettor stats!", e);
      return;
    }

    /* Write results to database. */
    if (connectionURL != null) {
      try {
        Map<String, Integer> updateRows = new HashMap<String, Integer>(),
            insertRows = new HashMap<String, Integer>();
        for (Map.Entry<String, Map<String, Integer>> e :
            data.entrySet()) {
          String date = e.getKey();
          Map<String, Integer> obs = e.getValue();
          for (String column : columns) {
            if (obs.containsKey(column)) {
              Integer value = obs.get(column);
              String key = date + "," + column;
              insertRows.put(key, value);
            }
          }
        }
        Connection conn = DriverManager.getConnection(connectionURL);
        PreparedStatement psI = conn.prepareStatement(
            "INSERT INTO gettor_stats (downloads, date, bundle) "
            + "VALUES (?, ?, ?)");
        PreparedStatement psU = conn.prepareStatement(
            "UPDATE gettor_stats SET downloads = ? "
            + "WHERE date = ? AND bundle = ?");
        conn.setAutoCommit(false);
        Statement statement = conn.createStatement();
        ResultSet rs = statement.executeQuery(
            "SELECT date, bundle, downloads FROM gettor_stats");
        while (rs.next()) {
          String date = rs.getDate(1).toString();
          String bundle = rs.getString(2);
          String key = date + "," + bundle;
          if (insertRows.containsKey(key)) {
            int insertRow = insertRows.remove(key);
            int oldCount = rs.getInt(3);
            if (insertRow != oldCount) {
              updateRows.put(key, insertRow);
            }
          }
        }
        for (Map.Entry<String, Integer> e : updateRows.entrySet()) {
          String[] keyParts = e.getKey().split(",");
          java.sql.Date date = java.sql.Date.valueOf(keyParts[0]);
          String bundle = keyParts[1];
          int downloads = e.getValue();
          psU.clearParameters();
          psU.setLong(1, downloads);
          psU.setDate(2, date);
          psU.setString(3, bundle);
          psU.executeUpdate();
        }
        for (Map.Entry<String, Integer> e : insertRows.entrySet()) {
          String[] keyParts = e.getKey().split(",");
          java.sql.Date date = java.sql.Date.valueOf(keyParts[0]);
          String bundle = keyParts[1];
          int downloads = e.getValue();
          psI.clearParameters();
          psI.setLong(1, downloads);
          psI.setDate(2, date);
          psI.setString(3, bundle);
          psI.executeUpdate();
        }
        conn.commit();
        conn.close();
      } catch (SQLException e) {
        logger.log(Level.WARNING, "Failed to add GetTor stats to "
            + "database.", e);
      }
    }

    logger.info("Finished downloading and processing statistics on Tor "
        + "packages delivered by GetTor.\nDownloaded " + unparsed.length()
        + " bytes. Last date in statistics is " + data.lastKey() + ".");
  }
}

