/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.text.*;
import java.util.*;
import java.util.logging.*;
import org.apache.commons.codec.*;
import org.apache.commons.codec.binary.*;
import org.apache.commons.codec.digest.*;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

public class BridgePoolAssignmentsProcessor {

  public BridgePoolAssignmentsProcessor(File assignmentsDirectory,
        File sanitizedAssignmentsDirectory) {

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
      } else {
        assignmentFiles.add(file);
      }
    }

    SimpleDateFormat assignmentFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    assignmentFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat filenameFormat =
        new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    filenameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    for (File assignmentFile : assignmentFiles) {
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
                File sanitizedAssignmentsFile = new File(
                    sanitizedAssignmentsDirectory, filenameFormat.format(
                    bridgePoolAssignmentTime));
                if (!sanitizedAssignmentsFile.exists()) {
                  sanitizedAssignmentsFile.getParentFile().mkdirs();
                  BufferedWriter bw = new BufferedWriter(new FileWriter(
                      sanitizedAssignmentsFile));
                  bw.write(bridgePoolAssignmentLine + "\n");
                  for (String assignmentLine : sanitizedAssignments) {
                    bw.write(assignmentLine + "\n");
                  }
                  bw.close();
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

    logger.info("Finished processing bridge pool assignment file(s).");
  }
}

