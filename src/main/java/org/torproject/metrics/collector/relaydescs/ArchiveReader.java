/* Copyright 2010--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.relaydescs;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;

/**
 * Read in all files in a given directory and pass buffered readers of
 * them to the relay descriptor parser.
 */
public class ArchiveReader {

  private static final Logger logger = LoggerFactory.getLogger(
      ArchiveReader.class);

  private Map<String, Set<String>> microdescriptorValidAfterTimes =
      new HashMap<>();

  private RelayDescriptorParser rdp;

  private File archivesDirectory;

  private boolean keepImportHistory;

  private int parsedFiles = 0;

  private int ignoredFiles = 0;

  private SortedSet<String> archivesImportHistory = new TreeSet<>();

  private File archivesImportHistoryFile;

  /** Initializes an archive reader but without reading any descriptors yet. */
  ArchiveReader(RelayDescriptorParser rdp, File archivesDirectory,
      File statsDirectory, boolean keepImportHistory) {
    if (rdp == null || archivesDirectory == null
        || statsDirectory == null) {
      throw new IllegalArgumentException();
    }
    this.rdp = rdp;
    this.rdp.setArchiveReader(this);
    this.archivesDirectory = archivesDirectory;
    this.keepImportHistory = keepImportHistory;
    this.archivesImportHistoryFile = new File(statsDirectory,
        "archives-import-history");
  }

  /** Reads all descriptors from the given directory, possibly using a
   * parse history file, and passes them to the given descriptor
   * parser. */
  public void readDescriptors() {
    this.readHistoryFile();
    this.readDescriptorFiles();
    this.writeHistoryFile();
  }

  private void readHistoryFile() {
    if (this.keepImportHistory && this.archivesImportHistoryFile.exists()) {
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            this.archivesImportHistoryFile));
        String line;
        while ((line = br.readLine()) != null) {
          this.archivesImportHistory.add(line);
        }
        br.close();
      } catch (IOException e) {
        logger.warn("Could not read in archives import "
            + "history file. Skipping.", e);
      }
    }
  }

  private void readDescriptorFiles() {
    if (this.archivesDirectory.exists()) {
      logger.debug("Importing files in directory {}/...",
          this.archivesDirectory);
      Stack<File> filesInInputDir = new Stack<>();
      filesInInputDir.add(this.archivesDirectory);
      List<File> problems = new ArrayList<>();
      Set<File> filesToRetry = new HashSet<>();
      while (!filesInInputDir.isEmpty()) {
        File pop = filesInInputDir.pop();
        if (pop.isDirectory()) {
          Collections.addAll(filesInInputDir, pop.listFiles());
        } else {
          try {
            BufferedInputStream bis;
            if (this.keepImportHistory
                && this.archivesImportHistory.contains(pop.getName())) {
              this.ignoredFiles++;
              continue;
            } else if (pop.getName().endsWith(".tar.bz2")) {
              logger.warn("Cannot parse compressed tarball {}. Skipping.",
                  pop.getAbsolutePath());
              continue;
            } else if (pop.getName().endsWith(".bz2")) {
              FileInputStream fis = new FileInputStream(pop);
              BZip2CompressorInputStream bcis =
                  new BZip2CompressorInputStream(fis);
              bis = new BufferedInputStream(bcis);
            } else {
              FileInputStream fis = new FileInputStream(pop);
              bis = new BufferedInputStream(fis);
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int len;
            byte[] data = new byte[1024];
            while ((len = bis.read(data, 0, 1024)) >= 0) {
              baos.write(data, 0, len);
            }
            bis.close();
            byte[] allData = baos.toByteArray();
            boolean stored = this.rdp.parse(allData, pop);
            if (!stored) {
              filesToRetry.add(pop);
              continue;
            }
            if (this.keepImportHistory) {
              this.archivesImportHistory.add(pop.getName());
            }
            this.parsedFiles++;
          } catch (IOException e) {
            problems.add(pop);
            if (problems.size() > 3) {
              break;
            }
          }
        }
      }
      for (File pop : filesToRetry) {
        /* TODO We need to parse microdescriptors ourselves, rather than
         * RelayDescriptorParser, because only we know the valid-after
         * time(s) of microdesc consensus(es) containing this
         * microdescriptor.  However, this breaks functional abstraction
         * pretty badly. */
        try {
          BufferedInputStream bis;
          if (pop.getName().endsWith(".bz2")) {
            FileInputStream fis = new FileInputStream(pop);
            BZip2CompressorInputStream bcis =
                new BZip2CompressorInputStream(fis);
            bis = new BufferedInputStream(bcis);
          } else {
            FileInputStream fis = new FileInputStream(pop);
            bis = new BufferedInputStream(fis);
          }
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          int len;
          byte[] data = new byte[1024];
          while ((len = bis.read(data, 0, 1024)) >= 0) {
            baos.write(data, 0, len);
          }
          bis.close();
          byte[] allData = baos.toByteArray();
          BufferedReader br = new BufferedReader(new StringReader(
              new String(allData, StandardCharsets.US_ASCII)));
          String line;
          do {
            line = br.readLine();
          } while (line != null && line.startsWith("@"));
          br.close();
          if (line == null) {
            logger.debug("We were given an empty descriptor for "
                + "parsing. Ignoring.");
            continue;
          }
          if (!line.equals("onion-key")) {
            logger.debug("Skipping non-recognized descriptor.");
            continue;
          }
          SimpleDateFormat parseFormat =
              new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
          parseFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
          String ascii = new String(allData, StandardCharsets.US_ASCII);
          int start;
          int end = -1;
          String startToken = "onion-key\n";
          while (end < ascii.length()) {
            start = ascii.indexOf(startToken, end);
            if (start < 0) {
              break;
            }
            end = ascii.indexOf(startToken, start + 1);
            if (end < 0) {
              end = ascii.length();
              if (end <= start) {
                break;
              }
            }
            byte[] descBytes = new byte[end - start];
            System.arraycopy(allData, start, descBytes, 0, end - start);
            String digest256Base64 = Base64.encodeBase64String(
                DigestUtils.sha256(descBytes)).replaceAll("=", "");
            String digest256Hex = DigestUtils.sha256Hex(descBytes);
            if (!this.microdescriptorValidAfterTimes.containsKey(
                digest256Hex)) {
              logger.debug("Could not store microdescriptor '{}', which was "
                  + "not contained in a microdesc consensus.", digest256Hex);
              continue;
            }
            for (String validAfterTime :
                this.microdescriptorValidAfterTimes.get(digest256Hex)) {
              try {
                long validAfter =
                    parseFormat.parse(validAfterTime).getTime();
                rdp.storeMicrodescriptor(descBytes, digest256Hex,
                    digest256Base64, validAfter);
              } catch (ParseException e) {
                logger.warn("Could not parse valid-after time '{}'. Not "
                    + "storing microdescriptor.", validAfterTime, e);
              }
            }
          }
          if (this.keepImportHistory) {
            this.archivesImportHistory.add(pop.getName());
          }
          this.parsedFiles++;
        } catch (IOException e) {
          problems.add(pop);
          if (problems.size() > 3) {
            break;
          }
        }
      }
      if (problems.isEmpty()) {
        logger.debug("Finished importing files in directory {}/.",
            this.archivesDirectory);
      } else {
        StringBuilder sb = new StringBuilder("Failed importing files in "
            + "directory " + this.archivesDirectory + "/:");
        int printed = 0;
        for (File f : problems) {
          sb.append("\n  ").append(f.getAbsolutePath());
          if (++printed >= 3) {
            sb.append("\n  ... more");
            break;
          }
        }
        logger.warn(sb.toString());
      }
    }
  }

  private void writeHistoryFile() {
    if (this.keepImportHistory) {
      try {
        this.archivesImportHistoryFile.getParentFile().mkdirs();
        BufferedWriter bw = new BufferedWriter(new FileWriter(
            this.archivesImportHistoryFile));
        for (String line : this.archivesImportHistory) {
          bw.write(line + "\n");
        }
        bw.close();
      } catch (IOException e) {
        logger.warn("Could not write archives import "
            + "history file.");
      }
    }
    logger.info("Finished importing relay descriptors from local directory:\n"
        + "Parsed {}, ignored {} files.", this.parsedFiles, this.ignoredFiles);
  }

  /** Stores the valid-after time and microdescriptor digests of a given
   * microdesc consensus, so that microdescriptors (which don't contain a
   * publication time) can later be sorted into the correct month
   * folders. */
  void haveParsedMicrodescConsensus(String validAfterTime,
      SortedSet<String> microdescriptorDigests) {
    for (String microdescriptor : microdescriptorDigests) {
      this.microdescriptorValidAfterTimes.putIfAbsent(microdescriptor,
          new HashSet<>());
      this.microdescriptorValidAfterTimes.get(microdescriptor).add(
          validAfterTime);
    }
  }
}

