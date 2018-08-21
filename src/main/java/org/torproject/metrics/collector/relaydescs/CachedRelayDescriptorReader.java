/* Copyright 2010--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.relaydescs;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;

/**
 * Parses all descriptors in local directory cacheddesc/ and sorts them
 * into directory structure in directory-archive/.
 */
public class CachedRelayDescriptorReader {

  private static final Logger logger = LoggerFactory.getLogger(
      CachedRelayDescriptorReader.class);

  private RelayDescriptorParser rdp;

  private String[] inputDirectories;

  private File importHistoryFile;

  private StringBuilder dumpStats;

  private Set<String> lastImportHistory = new HashSet<>();

  private Set<String> currentImportHistory = new HashSet<>();

  /** Initializes this reader but without starting to read yet. */
  CachedRelayDescriptorReader(RelayDescriptorParser rdp,
      String[] inputDirectories, File statsDirectory) {
    if (rdp == null || inputDirectories == null
        || inputDirectories.length == 0 || statsDirectory == null) {
      throw new IllegalArgumentException();
    }
    this.rdp = rdp;
    this.inputDirectories = inputDirectories;
    this.importHistoryFile = new File(statsDirectory,
        "cacheddesc-import-history");

    this.dumpStats = new StringBuilder("Finished importing "
        + "relay descriptors from local Tor data directories:");
  }

  /** Reads cached-descriptor files from one or more directories and
   * passes them to the given descriptor parser. */
  public void readDescriptors() {
    this.readHistoryFile();
    this.readDescriptorFiles();
    this.writeHistoryFile();
  }

  /** Read import history containing SHA-1 digests of previously parsed
   * statuses and descriptors, so that we can skip them in this run. */
  private void readHistoryFile() {
    if (importHistoryFile.exists()) {
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            importHistoryFile));
        String line;
        while ((line = br.readLine()) != null) {
          this.lastImportHistory.add(line);
        }
        br.close();
      } catch (IOException e) {
        logger.warn("Could not read import history from {}.",
            importHistoryFile.getAbsolutePath(), e);
      }
    }
  }

  /** Read cached descriptors directories. */
  private void readDescriptorFiles() {
    for (String inputDirectory : this.inputDirectories) {
      File cachedDescDir = new File(inputDirectory);
      if (!cachedDescDir.exists()) {
        logger.warn("Directory {} does not exist. Skipping.",
            cachedDescDir.getAbsolutePath());
        continue;
      }
      logger.debug("Reading {} directory.", cachedDescDir.getAbsolutePath());
      SortedSet<File> cachedDescFiles = new TreeSet<>();
      Stack<File> files = new Stack<>();
      files.add(cachedDescDir);
      while (!files.isEmpty()) {
        File file = files.pop();
        if (file.isDirectory()) {
          files.addAll(Arrays.asList(file.listFiles()));
        } else {
          cachedDescFiles.add(file);
        }
      }
      for (File f : cachedDescFiles) {
        try {
          // descriptors may contain non-ASCII chars; read as bytes to
          // determine digests
          BufferedInputStream bis =
              new BufferedInputStream(new FileInputStream(f));
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          int len;
          byte[] data = new byte[1024];
          while ((len = bis.read(data, 0, 1024)) >= 0) {
            baos.write(data, 0, len);
          }
          bis.close();
          byte[] allData = baos.toByteArray();
          if (f.getName().equals("cached-consensus")) {
            /* Check if directory information is stale. */
            BufferedReader br = new BufferedReader(new StringReader(
                new String(allData, "US-ASCII")));
            String line;
            while ((line = br.readLine()) != null) {
              if (line.startsWith("valid-after ")) {
                this.dumpStats.append("\n").append(f.getName()).append(": ")
                    .append(line.substring("valid-after ".length()));
                SimpleDateFormat dateTimeFormat =
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                if (dateTimeFormat.parse(line.substring("valid-after "
                    .length())).getTime() < System.currentTimeMillis()
                    - 6L * 60L * 60L * 1000L) {
                  logger.warn("Cached descriptor files in {} are stale. The "
                      + "valid-after line in cached-consensus is '{}'.",
                      cachedDescDir.getAbsolutePath(), line);
                  this.dumpStats.append(" (stale!)");
                }
                break;
              }
            }
            br.close();

            /* Parse the cached consensus if we haven't parsed it before
             * (but regardless of whether it's stale or not). */
            String digest = Hex.encodeHexString(DigestUtils.sha1(
                allData));
            if (!this.lastImportHistory.contains(digest)
                && !this.currentImportHistory.contains(digest)) {
              this.rdp.parse(allData);
            } else {
              this.dumpStats.append(" (skipped)");
            }
            this.currentImportHistory.add(digest);
          } else if (f.getName().equals("v3-status-votes")) {
            int parsedNum = 0;
            int skippedNum = 0;
            String ascii = new String(allData, "US-ASCII");
            String startToken = "network-status-version ";
            int end = ascii.length();
            int start = ascii.indexOf(startToken);
            while (start >= 0 && start < end) {
              int next = ascii.indexOf(startToken, start + 1);
              if (next < 0) {
                next = end;
              }
              if (start < next) {
                byte[] rawNetworkStatusBytes = new byte[next - start];
                System.arraycopy(allData, start, rawNetworkStatusBytes, 0,
                    next - start);
                String digest = Hex.encodeHexString(DigestUtils.sha1(
                    rawNetworkStatusBytes));
                if (!this.lastImportHistory.contains(digest)
                    && !this.currentImportHistory.contains(digest)) {
                  this.rdp.parse(rawNetworkStatusBytes);
                  parsedNum++;
                } else {
                  skippedNum++;
                }
                this.currentImportHistory.add(digest);
              }
              start = next;
            }
            this.dumpStats.append("\n").append(f.getName()).append(": parsed ")
                .append(parsedNum).append(", skipped ").append(skippedNum)
                .append(" votes");
          } else if (f.getName().startsWith("cached-descriptors")
              || f.getName().startsWith("cached-extrainfo")) {
            String ascii = new String(allData, "US-ASCII");
            int start;
            int sig;
            int end = -1;
            String startToken =
                f.getName().startsWith("cached-descriptors")
                    ? "router " : "extra-info ";
            String sigToken = "\nrouter-signature\n";
            String endToken = "\n-----END SIGNATURE-----\n";
            int parsedNum = 0;
            int skippedNum = 0;
            while (end < ascii.length()) {
              start = ascii.indexOf(startToken, end);
              if (start < 0) {
                break;
              }
              sig = ascii.indexOf(sigToken, start);
              if (sig < 0) {
                break;
              }
              sig += sigToken.length();
              end = ascii.indexOf(endToken, sig);
              if (end < 0) {
                break;
              }
              end += endToken.length();
              byte[] descBytes = new byte[end - start];
              System.arraycopy(allData, start, descBytes, 0, end - start);
              String digest = Hex.encodeHexString(DigestUtils.sha1(
                  descBytes));
              if (!this.lastImportHistory.contains(digest)
                  && !this.currentImportHistory.contains(digest)) {
                this.rdp.parse(descBytes);
                parsedNum++;
              } else {
                skippedNum++;
              }
              this.currentImportHistory.add(digest);
            }
            this.dumpStats.append("\n").append(f.getName()).append(": parsed ")
                .append(parsedNum).append(", skipped ").append(skippedNum)
                .append(" ").append(f.getName().startsWith("cached-descriptors")
                ? "server" : "extra-info").append(" descriptors");
          }
        } catch (IOException | ParseException e) {
          logger.warn("Failed reading {} directory.",
              cachedDescDir.getAbsolutePath(), e);
        }
      }
      logger.debug("Finished reading {} directory.",
          cachedDescDir.getAbsolutePath());
    }
  }

  /** Write import history containing SHA-1 digests to disk. */
  private void writeHistoryFile() {
    try {
      this.importHistoryFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.importHistoryFile));
      for (String digest : currentImportHistory) {
        bw.write(digest + "\n");
      }
      bw.close();
    } catch (IOException e) {
      logger.warn("Could not write import history to {}.",
          this.importHistoryFile.getAbsolutePath(), e);
    }

    logger.info(dumpStats.toString());
  }
}

