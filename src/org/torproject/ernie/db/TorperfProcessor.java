/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.logging.*;

public class TorperfProcessor {
  public TorperfProcessor(String torperfDirectory, String connectionURL) {
    Logger logger = Logger.getLogger(TorperfProcessor.class.getName());
    File rawFile = new File("stats/torperf-raw");
    File statsFile = new File("stats/torperf-stats");
    File torperfDir = new File(torperfDirectory);
    SortedMap<String, String> rawObs = new TreeMap<String, String>();
    SortedMap<String, String> stats = new TreeMap<String, String>();
    int addedRawObs = 0;
    try {
      if (rawFile.exists()) {
        logger.fine("Reading file " + rawFile.getAbsolutePath() + "...");
        BufferedReader br = new BufferedReader(new FileReader(rawFile));
        String line = br.readLine(); // ignore header
        while ((line = br.readLine()) != null) {
          if (line.split(",").length != 4) {
            logger.warning("Corrupt line in " + rawFile.getAbsolutePath()
                + "!");
            break;
          }
          String key = line.substring(0, line.lastIndexOf(","));
          if (line.substring(line.lastIndexOf(",") + 1).startsWith("-")) {
            /* If completion time is negative, this is because we had an
             * integer overflow bug. Fix this. */
            long newValue = Long.parseLong(line.substring(
                line.lastIndexOf(",") + 1)) + 100000000L;
            line = key + "," + newValue;
          }
          rawObs.put(key, line);
        }
        br.close();
        logger.fine("Finished reading file " + rawFile.getAbsolutePath()
            + ".");
      }
      if (statsFile.exists()) {
        logger.fine("Reading file " + statsFile.getAbsolutePath()
            + "...");
        BufferedReader br = new BufferedReader(new FileReader(statsFile));
        String line = br.readLine(); // ignore header
        while ((line = br.readLine()) != null) {
          String key = line.split(",")[0] + "," + line.split(",")[1];
          stats.put(key, line);
        }
        br.close();
        logger.fine("Finished reading file " + statsFile.getAbsolutePath()
            + ".");
      }
      if (torperfDir.exists()) {
        logger.fine("Importing files in " + torperfDirectory + "/...");
        Stack<File> filesInInputDir = new Stack<File>();
        filesInInputDir.add(torperfDir);
        while (!filesInInputDir.isEmpty()) {
          File pop = filesInInputDir.pop();
          if (pop.isDirectory()) {
            for (File f : pop.listFiles()) {
              filesInInputDir.add(f);
            }
          } else {
            String source = pop.getName().substring(0,
                pop.getName().indexOf("."));
            String size = pop.getName().split("-")[1];
            long receivedBytes = 1L;
            if (pop.getName().endsWith("kb.data")) {
              receivedBytes *= 1024L;
            } else if (pop.getName().endsWith("mb.data")) {
              receivedBytes *= 1024L * 1024L;
            } else {
              // not a valid .data file
              continue;
            }
            receivedBytes *= Long.parseLong(size.substring(0,
                size.length() - "xb.data".length()));
            BufferedReader br = new BufferedReader(new FileReader(pop));
            String line = null;
            SimpleDateFormat formatter =
                new SimpleDateFormat("yyyy-MM-dd,HH:mm:ss");
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
            while ((line = br.readLine()) != null) {
              String[] parts = line.split(" ");
              // remove defective lines as they occurred on gabelmoo as well
              // as incomplete downloads
              if (parts.length == 20 && parts[0].length() == 10
                  && !parts[16].equals("0")
                  && Long.parseLong(parts[19]) > receivedBytes) {
                long startSec = Long.parseLong(parts[0]);
                String dateTime = formatter.format(startSec * 1000L);
                long completeMillis = Long.parseLong(parts[16])
                    * 1000L + Long.parseLong(parts[17]) / 1000L
                    - Long.parseLong(parts[0]) * 1000L
                    + Long.parseLong(parts[1]) / 1000L;
                String key = source + "," + dateTime;
                String value = key + "," + completeMillis;
                if (!rawObs.containsKey(key)) {
                  rawObs.put(key, value);
                  addedRawObs++;
                  // TODO if torperf-stats generation takes long, compile
                  // list of dates that have changes for torperf-stats and
                  // only re-generate those
                }
              }
            }
            br.close();
          }
        }
        logger.fine("Finished importing files in " + torperfDirectory
            + "/.");
      }
      if (rawObs.size() > 0) {
        logger.fine("Writing file " + rawFile.getAbsolutePath() + "...");
        rawFile.getParentFile().mkdirs();
        BufferedWriter bw = new BufferedWriter(new FileWriter(rawFile));
        bw.append("source,date,start,completemillis\n");
        String tempSourceDate = null;
        Iterator<Map.Entry<String, String>> it =
            rawObs.entrySet().iterator();
        List<Long> dlTimes = new ArrayList<Long>();
        boolean haveWrittenFinalLine = false;
        SortedMap<String, List<Long>> dlTimesAllSources =
            new TreeMap<String, List<Long>>();
        while (it.hasNext() || !haveWrittenFinalLine) {
          Map.Entry<String, String> next = it.hasNext() ? it.next() : null;
          if (tempSourceDate != null
              && (next == null || !(next.getValue().split(",")[0] + ","
              + next.getValue().split(",")[1]).equals(tempSourceDate))) {
            if (dlTimes.size() > 4) {
              Collections.sort(dlTimes);
              long q1 = dlTimes.get(dlTimes.size() / 4 - 1);
              long md = dlTimes.get(dlTimes.size() / 2 - 1);
              long q3 = dlTimes.get(dlTimes.size() * 3 / 4 - 1);
              stats.put(tempSourceDate, tempSourceDate + "," + q1 + ","
                  + md + "," + q3);
              String allSourceDate = "all" + tempSourceDate.substring(
                  tempSourceDate.indexOf("-"));
              if (dlTimesAllSources.containsKey(allSourceDate)) {
                dlTimesAllSources.get(allSourceDate).addAll(dlTimes);
              } else {
                dlTimesAllSources.put(allSourceDate, dlTimes);
              }
            }
            dlTimes = new ArrayList<Long>();
            if (next == null) {
              haveWrittenFinalLine = true;
            }
          }
          if (next != null) {
            bw.append(next.getValue() + "\n");
            String[] parts = next.getValue().split(",");
            tempSourceDate = parts[0] + "," + parts[1];
            dlTimes.add(Long.parseLong(parts[3]));
          }
        }
        bw.close();
        for (Map.Entry<String, List<Long>> e :
            dlTimesAllSources.entrySet()) {
          String allSourceDate = e.getKey();
          dlTimes = e.getValue();
          Collections.sort(dlTimes);
          long q1 = dlTimes.get(dlTimes.size() / 4 - 1);
          long md = dlTimes.get(dlTimes.size() / 2 - 1);
          long q3 = dlTimes.get(dlTimes.size() * 3 / 4 - 1);
          stats.put(allSourceDate, allSourceDate + "," + q1 + "," + md
              + "," + q3);
        }
        logger.fine("Finished writing file " + rawFile.getAbsolutePath()
            + ".");
      }
      if (stats.size() > 0) {
        logger.fine("Writing file " + statsFile.getAbsolutePath()
            + "...");
        statsFile.getParentFile().mkdirs();
        BufferedWriter bw = new BufferedWriter(new FileWriter(statsFile));
        bw.append("source,date,q1,md,q3\n");
        // TODO should we handle missing days?
        for (String s : stats.values()) {
          bw.append(s + "\n");
        }
        bw.close();
        logger.fine("Finished writing file " + statsFile.getAbsolutePath()
            + ".");
      }
    } catch (IOException e) {
      logger.log(Level.WARNING, "Failed writing "
          + rawFile.getAbsolutePath() + " or "
          + statsFile.getAbsolutePath() + "!", e);
    }

    /* Write stats. */
    StringBuilder dumpStats = new StringBuilder("Finished writing "
        + "statistics on torperf results.\nAdded " + addedRawObs
        + " new observations in this execution.\n"
        + "Last known obserations by source and file size are:");
    String lastSource = null;
    String lastLine = null;
    for (String s : rawObs.keySet()) {
      String[] parts = s.split(",");
      if (lastSource == null) {
        lastSource = parts[0];
      } else if (!parts[0].equals(lastSource)) {
        dumpStats.append("\n" + lastSource + " " + lastLine.split(",")[1]
            + " " + lastLine.split(",")[2]);
        lastSource = parts[0];
      }
      lastLine = s;
    }
    if (lastSource != null) {
      dumpStats.append("\n" + lastSource + " " + lastLine.split(",")[1]
          + " " + lastLine.split(",")[2]);
    }
    logger.info(dumpStats.toString());

    /* Write results to database. */
    if (connectionURL != null) {
      try {
        Map<String, String> insertRows = new HashMap<String, String>();
        insertRows.putAll(stats);
        Set<String> updateRows = new HashSet<String>();
        Connection conn = DriverManager.getConnection(connectionURL);
        conn.setAutoCommit(false);
        Statement statement = conn.createStatement();
        ResultSet rs = statement.executeQuery(
            "SELECT date, source, q1, md, q3 FROM torperf_stats");
        while (rs.next()) {
          String date = rs.getDate(1).toString();
          String source = rs.getString(2);
          String key = source + "," + date;
          if (insertRows.containsKey(key)) {
            String insertRow = insertRows.remove(key);
            String[] newStats = insertRow.split(",");
            long newQ1 = Long.parseLong(newStats[2]);
            long newMd = Long.parseLong(newStats[3]);
            long newQ3 = Long.parseLong(newStats[4]);
            long oldQ1 = rs.getLong(3);
            long oldMd = rs.getLong(4);
            long oldQ3 = rs.getLong(5);
            if (newQ1 != oldQ1 || newMd != oldMd || newQ3 != oldQ3) {
              updateRows.add(insertRow);
            }
          }
        }
        PreparedStatement psU = conn.prepareStatement(
            "UPDATE torperf_stats SET q1 = ?, md = ?, q3 = ? "
            + "WHERE date = ? AND source = ?");
        for (String row : updateRows) {
          String[] newStats = row.split(",");
          String source = newStats[0];
          java.sql.Date date = java.sql.Date.valueOf(newStats[1]);
          long q1 = Long.parseLong(newStats[2]);
          long md = Long.parseLong(newStats[3]);
          long q3 = Long.parseLong(newStats[4]);
          psU.clearParameters();
          psU.setLong(1, q1);
          psU.setLong(2, md);
          psU.setLong(3, q3);
          psU.setDate(4, date);
          psU.setString(5, source);
          psU.executeUpdate();
        }
        PreparedStatement psI = conn.prepareStatement(
            "INSERT INTO torperf_stats (q1, md, q3, date, source) "
            + "VALUES (?, ?, ?, ?, ?)");
        for (String row : insertRows.values()) {
          String[] newStats = row.split(",");
          String source = newStats[0];
          java.sql.Date date = java.sql.Date.valueOf(newStats[1]);
          long q1 = Long.parseLong(newStats[2]);
          long md = Long.parseLong(newStats[3]);
          long q3 = Long.parseLong(newStats[4]);
          psI.clearParameters();
          psI.setLong(1, q1);
          psI.setLong(2, md);
          psI.setLong(3, q3);
          psI.setDate(4, date);
          psI.setString(5, source);
          psI.executeUpdate();
        }
        conn.commit();
        conn.close();
      } catch (SQLException e) {
        logger.log(Level.WARNING, "Failed to add torperf stats to "
            + "database.", e);
      }
    }
  }
}

