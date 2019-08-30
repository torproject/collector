/* Copyright 2011--2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgepools;

import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.Stack;
import java.util.TreeMap;

public class BridgePoolAssignmentsProcessor extends CollecTorMain {

  /**
   * Class logger.
   */
  private static final Logger logger = LoggerFactory.getLogger(
      BridgePoolAssignmentsProcessor.class);

  /**
   * Directory containing original, not-yet-sanitized bridge pool assignment
   * files.
   */
  private File assignmentsDirectory;

  /**
   * Directory containing sanitized bridge pool assignments for tarballs.
   */
  private String outputPathName;

  /**
   * Directory containing recently stored sanitized bridge pool assignments.
   */
  private String recentPathName;

  /**
   * Timestamp format in bridge-pool-assignments line.
   */
  private DateTimeFormatter assignmentFormat = DateTimeFormatter.ofPattern(
      "uuuu-MM-dd HH:mm:ss");

  /**
   * File name format.
   */
  private DateTimeFormatter filenameFormat = DateTimeFormatter.ofPattern(
      "uuuu/MM/dd/uuuu-MM-dd-HH-mm-ss");

  /**
   * Initialize this class with the given configuration.
   */
  public BridgePoolAssignmentsProcessor(Configuration config) {
    super(config);
  }

  /**
   * Return the module identifier.
   *
   * @return Module identifier.
   */
  @Override
  public String module() {
    return "BridgePoolAssignments";
  }

  /**
   * Return the synchronization marker.
   *
   * @return Synchronization marker.
   */
  @Override
  protected String syncMarker() {
    return "BridgePoolAssignments";
  }

  /**
   * Start processing files, which includes reading original, not-yet-sanitized
   * bridge pool assignment files from disk, splitting them into bridge pool
   * assignment descriptors, sanitizing contained fingerprints, and writing
   * sanitized bridge pool assignments to disk.
   *
   * @throws ConfigurationException Thrown if configuration values cannot be
   *     obtained.
   */
  @Override
  protected void startProcessing() throws ConfigurationException {
    logger.info("Starting bridge-pool-assignments module of CollecTor.");
    this.initializeConfiguration();
    List<File> assignmentFiles = this.listAssignmentFiles();
    for (File assignmentFile : assignmentFiles) {
      logger.info("Processing bridge pool assignment file '{}'...",
          assignmentFile.getAbsolutePath());
      for (Map.Entry<LocalDateTime, SortedMap<String, String>> e
           : this.readBridgePoolAssignments(assignmentFile).entrySet()) {
        LocalDateTime published = e.getKey();
        SortedMap<String, String> originalAssignments = e.getValue();
        SortedMap<String, String> sanitizedAssignments
            = this.sanitizeAssignments(originalAssignments);
        if (null == sanitizedAssignments) {
          logger.warn("Unable to sanitize assignments published at {}. "
              + "Skipping.", published);
          continue;
        }
        String formattedSanitizedAssignments = this.formatSanitizedAssignments(
            published, sanitizedAssignments);
        File tarballFile = Paths.get(this.outputPathName,
            published.format(this.filenameFormat)).toFile();
        File rsyncFile = new File(this.recentPathName,
            tarballFile.getName());
        File[] outputFiles = new File[] { tarballFile, rsyncFile };
        for (File outputFile : outputFiles) {
          if (!outputFile.exists()) {
            this.writeSanitizedAssignmentsToFile(outputFile,
                formattedSanitizedAssignments);
          }
        }
      }
    }
    this.cleanUpRsyncDirectory();
    logger.info("Finished processing bridge pool assignment file(s).");
  }

  /**
   * Initialize configuration by obtaining current configuration values and
   * storing them in instance attributes.
   */
  private void initializeConfiguration() throws ConfigurationException {
    this.outputPathName = Paths.get(config.getPath(Key.OutputPath).toString(),
        "bridge-pool-assignments").toString();
    this.recentPathName = Paths.get(config.getPath(Key.RecentPath).toString(),
        "bridge-pool-assignments").toString();
    this.assignmentsDirectory =
        config.getPath(Key.BridgePoolAssignmentsLocalOrigins).toFile();
  }

  /**
   * Compile a list of all assignment files in the input directory.
   *
   * @return List of assignment files.
   */
  private List<File> listAssignmentFiles() {
    List<File> assignmentFiles = new ArrayList<>();
    Stack<File> files = new Stack<>();
    files.add(this.assignmentsDirectory);
    while (!files.isEmpty()) {
      File file = files.pop();
      if (file.isDirectory()) {
        File[] filesInDirectory = file.listFiles();
        if (null != filesInDirectory) {
          files.addAll(Arrays.asList(filesInDirectory));
        }
      } else if (file.getName().startsWith("assignments.log")) {
        assignmentFiles.add(file);
      }
    }
    return assignmentFiles;
  }

  /**
   * Read one or more bridge pool assignments from the given file and store them
   * in a map with keys being published timestamps and values being maps of
   * (original, not-yet-sanitized) fingerprints and assignment details.
   *
   * @param assignmentFile File containing one or more bridge pool assignments.
   * @return Map containing all read bridge pool assignments.
   */
  private SortedMap<LocalDateTime, SortedMap<String, String>>
      readBridgePoolAssignments(File assignmentFile) {
    SortedMap<LocalDateTime, SortedMap<String, String>>
        readBridgePoolAssignments = new TreeMap<>();
    try {
      BufferedReader br;
      if (assignmentFile.getName().endsWith(".gz")) {
        br = new BufferedReader(new InputStreamReader(
            new GzipCompressorInputStream(new FileInputStream(
                assignmentFile))));
      } else {
        br = new BufferedReader(new FileReader(assignmentFile));
      }
      String line;
      SortedMap<String, String> currentAssignments = null;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("bridge-pool-assignment ")) {
          try {
            LocalDateTime bridgePoolAssignmentTime = LocalDateTime.parse(
                line.substring("bridge-pool-assignment ".length()),
                this.assignmentFormat);
            if (readBridgePoolAssignments.containsKey(
                bridgePoolAssignmentTime)) {
              logger.warn("Input file {} contains duplicate line: {}. "
                  + "Discarding previously read line and subsequent assignment "
                  + "lines.", assignmentFile, line);
            }
            currentAssignments = new TreeMap<>();
            readBridgePoolAssignments.put(bridgePoolAssignmentTime,
                currentAssignments);
          } catch (DateTimeException e) {
            logger.warn("Could not parse timestamp from line {}. Skipping "
                    + "bridge pool assignment file '{}'.", line,
                assignmentFile.getAbsolutePath(), e);
            break;
          }
        } else if (null == currentAssignments) {
          logger.warn("Input file {} does not start with a "
              + "bridge-pool-assignments line. Skipping.",
              assignmentFile);
          break;
        } else {
          String[] parts = line.split(" ", 2);
          if (parts.length < 2 || parts[0].length() < 40) {
            logger.warn("Unrecognized line '{}'. Aborting.", line);
            break;
          }
          if (currentAssignments.containsKey(parts[0])) {
            logger.warn("Input file {} contains duplicate line: {}. "
                + "Discarding previously read line.", assignmentFile, line);
          }
          currentAssignments.put(parts[0], parts[1]);
        }
      }
      br.close();
    } catch (IOException e) {
      logger.warn("Could not read bridge pool assignment file '{}'. "
          + "Skipping.", assignmentFile.getAbsolutePath(), e);
    }
    if (!readBridgePoolAssignments.isEmpty()
        && readBridgePoolAssignments.lastKey().minusMinutes(330L)
        .isBefore(LocalDateTime.now())) {
      logger.warn("The last known bridge pool assignment list was "
          + "published at {}, which is more than 5:30 hours in the past.",
          readBridgePoolAssignments.lastKey());
    }
    return readBridgePoolAssignments;
  }

  /**
   * Sanitize the given bridge pool assignments by returning a new map with keys
   * being SHA-1 digests of keys found in the given map.
   *
   * @param originalAssignments Map of (original, not-yet-sanitized)
   *     fingerprints to assignment details.
   * @return Map of sanitized fingerprints to assignment details.
   */
  private SortedMap<String, String> sanitizeAssignments(
      SortedMap<String, String> originalAssignments) {
    SortedMap<String, String> sanitizedAssignments = new TreeMap<>();
    for (Map.Entry<String, String> e : originalAssignments.entrySet()) {
      String originalFingerprint = e.getKey();
      String assignmentDetails = e.getValue();
      try {
        String hashedFingerprint = Hex.encodeHexString(DigestUtils.sha1(
            Hex.decodeHex(originalFingerprint.toCharArray()))).toLowerCase();
        sanitizedAssignments.put(hashedFingerprint, assignmentDetails);
      } catch (DecoderException ex) {
        logger.warn("Unable to decode hex fingerprint. Aborting.", ex);
        return null;
      }
    }
    return sanitizedAssignments;
  }

  /**
   * Format sanitized bridge pool assignments consisting of a published
   * timestamp and a map of sanitized fingerprints to assignment details as a
   * single string.
   *
   * @param published Published timestamp as found in the bridge-pool-assignment
   *     line.
   * @param sanitizedAssignments Map of sanitized fingerprints to assignment
   *     details.
   * @return Formatted sanitized bridge pool assignments.
   */
  private String formatSanitizedAssignments(LocalDateTime published,
      SortedMap<String, String> sanitizedAssignments) {
    StringBuilder sb = new StringBuilder();
    sb.append("@type bridge-pool-assignment 1.0\n");
    sb.append(String.format("bridge-pool-assignment %s\n",
        published.format(this.assignmentFormat)));
    for (Map.Entry<String, String> e : sanitizedAssignments.entrySet()) {
      sb.append(String.format("%s %s%n", e.getKey(), e.getValue()));
    }
    return sb.toString();
  }

  /**
   * Write the given formatted sanitized bridge pool assignments to the given
   * file, or if that fails for any reason, log a warning and exit.
   *
   * @param outputFile File to write to.
   * @param formattedSanitizedAssignments Formatted sanitized bridge pool
   *     assignments to write.
   */
  private void writeSanitizedAssignmentsToFile(File outputFile,
      String formattedSanitizedAssignments) {
    if (!outputFile.getParentFile().exists()
        && !outputFile.getParentFile().mkdirs()) {
      logger.warn("Could not create parent directories of {}.", outputFile);
      return;
    }
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile))) {
      bw.write(formattedSanitizedAssignments);
    } catch (IOException e) {
      logger.warn("Unable to write sanitized bridge pool assignments to {}.",
          outputFile, e);
    }
  }

  /**
   * Delete all files from the rsync directory that have not been modified in
   * the last three days.
   */
  public void cleanUpRsyncDirectory() {
    Instant cutOff = Instant.now().minus(3L, ChronoUnit.DAYS);
    Stack<File> allFiles = new Stack<>();
    allFiles.add(new File(this.recentPathName));
    while (!allFiles.isEmpty()) {
      File file = allFiles.pop();
      if (file.isDirectory()) {
        File[] filesInDirectory = file.listFiles();
        if (null != filesInDirectory) {
          allFiles.addAll(Arrays.asList(filesInDirectory));
        }
      } else if (Instant.ofEpochMilli(file.lastModified()).isBefore(cutOff)) {
        try {
          Files.deleteIfExists(file.toPath());
        } catch (IOException e) {
          logger.warn("Unable to delete file {} that is apparently older than "
              + "three days.", file, e);
        }
      }
    }
  }
}


