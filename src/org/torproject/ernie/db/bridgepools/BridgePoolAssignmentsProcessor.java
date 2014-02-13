/* Copyright 2011--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.bridgepools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.torproject.ernie.db.main.Configuration;
import org.torproject.ernie.db.main.LockFile;
import org.torproject.ernie.db.main.LoggingConfiguration;

public class BridgePoolAssignmentsProcessor extends Thread {

  public static void main(String[] args) {

    /* Initialize logging configuration. */
    new LoggingConfiguration("bridge-pool-assignments");
    Logger logger = Logger.getLogger(
        BridgePoolAssignmentsProcessor.class.getName());
    logger.info("Starting bridge-pool-assignments module of ERNIE.");

    // Initialize configuration
    Configuration config = new Configuration();

    // Use lock file to avoid overlapping runs
    LockFile lf = new LockFile("bridge-pool-assignments");
    if (!lf.acquireLock()) {
      logger.severe("Warning: ERNIE is already running or has not exited "
          + "cleanly! Exiting!");
      System.exit(1);
    }

    // Process bridge pool assignments
    new BridgePoolAssignmentsProcessor(config).run();

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating bridge-pool-assignments module of ERNIE.");
  }

  private Configuration config;

  public BridgePoolAssignmentsProcessor(Configuration config) {
    this.config = config;
  }

  public void run() {

    File assignmentsDirectory =
        new File(config.getAssignmentsDirectory());
    File sanitizedAssignmentsDirectory =
        new File(config.getSanitizedAssignmentsDirectory());

    Logger logger =
        Logger.getLogger(BridgePoolAssignmentsProcessor.class.getName());
    if (assignmentsDirectory == null ||
        sanitizedAssignmentsDirectory == null) {
      IllegalArgumentException e = new IllegalArgumentException("Neither "
          + "assignmentsDirectory nor sanitizedAssignmentsDirectory may "
          + "be null!");
      throw e;
    }

    List<File> assignmentFiles = new ArrayList<File>();
    Stack<File> files = new Stack<File>();
    files.add(assignmentsDirectory);
    while (!files.isEmpty()) {
      File file = files.pop();
      if (file.isDirectory()) {
        files.addAll(Arrays.asList(file.listFiles()));
      } else if (file.getName().equals("assignments.log")) {
        assignmentFiles.add(file);
      }
    }

    SimpleDateFormat assignmentFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    assignmentFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat filenameFormat =
        new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    filenameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    String duplicateFingerprint = null;
    long maxBridgePoolAssignmentTime = 0L;
    for (File assignmentFile : assignmentFiles) {
      logger.info("Processing bridge pool assignment file '"
          + assignmentFile.getAbsolutePath() + "'...");
      try {
        BufferedReader br = null;
        if (assignmentFile.getName().endsWith(".gz")) {
          br = new BufferedReader(new InputStreamReader(
              new GzipCompressorInputStream(new FileInputStream(
                  assignmentFile))));
        } else {
          br = new BufferedReader(new FileReader(assignmentFile));
        }
        String line, bridgePoolAssignmentLine = null;
        SortedSet<String> sanitizedAssignments = new TreeSet<String>();
        boolean wroteLastLine = false, skipBefore20120504125947 = true;
        Set<String> hashedFingerprints = null;
        while ((line = br.readLine()) != null || !wroteLastLine) {
          if (line != null && line.startsWith("bridge-pool-assignment ")) {
            String[] parts = line.split(" ");
            if (parts.length != 3) {
              continue;
            }
            /* TODO Take out this temporary hack to ignore all assignments
             * coming from ponticum when byblos was still the official
             * BridgeDB host. */
            if (line.compareTo(
                "bridge-pool-assignment 2012-05-04 12:59:47") >= 0) {
              skipBefore20120504125947 = false;
            }
          }
          if (skipBefore20120504125947) {
            if (line == null) {
              break;
            } else {
              continue;
            }
          }
          if (line == null ||
              line.startsWith("bridge-pool-assignment ")) {
            if (bridgePoolAssignmentLine != null) {
              try {
                long bridgePoolAssignmentTime = assignmentFormat.parse(
                    bridgePoolAssignmentLine.substring(
                    "bridge-pool-assignment ".length())).getTime();
                maxBridgePoolAssignmentTime = Math.max(
                    maxBridgePoolAssignmentTime,
                    bridgePoolAssignmentTime);
                File tarballFile = new File(
                    sanitizedAssignmentsDirectory, filenameFormat.format(
                    bridgePoolAssignmentTime));
                File rsyncFile = new File(
                    "rsync/bridge-pool-assignments/"
                    + tarballFile.getName());
                File[] outputFiles = new File[] { tarballFile,
                    rsyncFile };
                for (File outputFile : outputFiles) {
                  if (!outputFile.exists()) {
                    outputFile.getParentFile().mkdirs();
                    BufferedWriter bw = new BufferedWriter(new FileWriter(
                        outputFile));
                    bw.write("@type bridge-pool-assignment 1.0\n");
                    bw.write(bridgePoolAssignmentLine + "\n");
                    for (String assignmentLine : sanitizedAssignments) {
                      bw.write(assignmentLine + "\n");
                    }
                    bw.close();
                  }
                }
              } catch (IOException e) {
                logger.log(Level.WARNING, "Could not write sanitized "
                    + "bridge pool assignment file for line '"
                    + bridgePoolAssignmentLine + "' to disk. Skipping "
                    + "bridge pool assignment file '"
                    + assignmentFile.getAbsolutePath() + "'.", e);
                break;
              } catch (ParseException e) {
                logger.log(Level.WARNING, "Could not write sanitized "
                    + "bridge pool assignment file for line '"
                    + bridgePoolAssignmentLine + "' to disk. Skipping "
                    + "bridge pool assignment file '"
                    + assignmentFile.getAbsolutePath() + "'.", e);
                break;
              }
              sanitizedAssignments.clear();
            }
            if (line == null) {
              wroteLastLine = true;
            } else {
              bridgePoolAssignmentLine = line;
              hashedFingerprints = new HashSet<String>();
            }
          } else {
            String[] parts = line.split(" ");
            if (parts.length < 2 || parts[0].length() < 40) {
              logger.warning("Unrecognized line '" + line
                  + "'. Aborting.");
              break;
            }
            String hashedFingerprint = null;
            try {
              hashedFingerprint = DigestUtils.shaHex(Hex.decodeHex(
                  line.split(" ")[0].toCharArray())).toLowerCase();
            } catch (DecoderException e) {
              logger.warning("Unable to decode hex fingerprint in line '"
                  + line + "'. Aborting.");
              break;
            }
            if (hashedFingerprints.contains(hashedFingerprint)) {
              duplicateFingerprint = bridgePoolAssignmentLine;
            }
            hashedFingerprints.add(hashedFingerprint);
            String assignmentDetails = line.substring(40);
            sanitizedAssignments.add(hashedFingerprint
                + assignmentDetails);
          }
        }
        br.close();
      } catch (IOException e) {
        logger.log(Level.WARNING, "Could not read bridge pool assignment "
            + "file '" + assignmentFile.getAbsolutePath()
            + "'. Skipping.", e);
      }
    }

    if (duplicateFingerprint != null) {
      logger.warning("At least one bridge pool assignment list contained "
          + "duplicate fingerprints.  Last found in assignment list "
          + "starting with '" + duplicateFingerprint + "'.");
    }

    if (maxBridgePoolAssignmentTime > 0L &&
        maxBridgePoolAssignmentTime + 330L * 60L * 1000L
        < System.currentTimeMillis()) {
      SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      logger.warning("The last known bridge pool assignment list was "
          + "published at "
          + dateTimeFormat.format(maxBridgePoolAssignmentTime)
          + ", which is more than 5:30 hours in the past.");
    }

    this.cleanUpRsyncDirectory();

    logger.info("Finished processing bridge pool assignment file(s).");
  }

  /* Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<File>();
    allFiles.add(new File("rsync/bridge-pool-assignments"));
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

