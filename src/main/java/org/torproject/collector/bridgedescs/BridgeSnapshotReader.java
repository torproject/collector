/* Copyright 2010--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import org.torproject.collector.conf.ConfigurationException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
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
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeSet;

public class BridgeSnapshotReader {

  private static final Logger logger = LoggerFactory.getLogger(
      BridgeSnapshotReader.class);

  /**
   * Reads the half-hourly snapshots of bridge descriptors from Bifroest.
   */
  public BridgeSnapshotReader(BridgeDescriptorParser bdp,
      File bridgeDirectoriesDir, File statsDirectory)
      throws ConfigurationException {

    if (bdp == null || bridgeDirectoriesDir == null
        || statsDirectory == null) {
      throw new IllegalArgumentException();
    }

    SortedSet<String> parsed = new TreeSet<String>();
    File bdDir = bridgeDirectoriesDir;
    File pbdFile = new File(statsDirectory, "parsed-bridge-directories");
    boolean modified = false;
    if (bdDir.exists()) {
      if (pbdFile.exists()) {
        logger.debug("Reading file " + pbdFile.getAbsolutePath() + "...");
        try {
          BufferedReader br = new BufferedReader(new FileReader(pbdFile));
          String line = null;
          while ((line = br.readLine()) != null) {
            parsed.add(line);
          }
          br.close();
          logger.debug("Finished reading file "
              + pbdFile.getAbsolutePath() + ".");
        } catch (IOException e) {
          logger.warn("Failed reading file "
              + pbdFile.getAbsolutePath() + "!", e);
          return;
        }
      }
      logger.debug("Importing files in directory " + bridgeDirectoriesDir
          + "/...");
      Set<String> descriptorImportHistory = new HashSet<String>();
      int parsedFiles = 0;
      int skippedFiles = 0;
      int parsedStatuses = 0;
      int parsedServerDescriptors = 0;
      int skippedServerDescriptors = 0;
      int parsedExtraInfoDescriptors = 0;
      int skippedExtraInfoDescriptors = 0;
      Stack<File> filesInInputDir = new Stack<File>();
      filesInInputDir.add(bdDir);
      while (!filesInInputDir.isEmpty()) {
        File pop = filesInInputDir.pop();
        if (pop.isDirectory()) {
          for (File f : pop.listFiles()) {
            filesInInputDir.add(f);
          }
        } else if (!parsed.contains(pop.getName())) {
          try {
            FileInputStream in = new FileInputStream(pop);
            if (in.available() > 0) {
              TarArchiveInputStream tais = null;
              if (pop.getName().endsWith(".tar.gz")) {
                GzipCompressorInputStream gcis =
                    new GzipCompressorInputStream(in);
                tais = new TarArchiveInputStream(gcis);
              } else if (pop.getName().endsWith(".tar")) {
                tais = new TarArchiveInputStream(in);
              } else {
                continue;
              }
              BufferedInputStream bis = new BufferedInputStream(tais);
              String fn = pop.getName();
              String[] fnParts = fn.split("-");
              if (fnParts.length != 5) {
                logger.warn("Invalid bridge descriptor tarball file name: "
                    + fn + ".  Skipping.");
                continue;
              }
              String authorityPart = String.format("%s-%s-", fnParts[0],
                  fnParts[1]);
              String datePart = String.format("%s-%s-%s", fnParts[2],
                  fnParts[3], fnParts[4]);
              String authorityFingerprint;
              switch (authorityPart) {
                case "from-tonga-":
                  authorityFingerprint =
                      "4A0CCD2DDC7995083D73F5D667100C8A5831F16D";
                  break;
                case "from-bifroest-":
                  authorityFingerprint =
                      "1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1";
                  break;
                default:
                  logger.warn("Did not recognize the bridge authority that "
                      + "generated " + fn + ".  Skipping.");
                  continue;
              }
              String dateTime = datePart.substring(0, 10) + " "
                  + datePart.substring(11, 13) + ":"
                  + datePart.substring(13, 15) + ":"
                  + datePart.substring(15, 17);
              while ((tais.getNextTarEntry()) != null) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                int len;
                byte[] data = new byte[1024];
                while ((len = bis.read(data, 0, 1024)) >= 0) {
                  baos.write(data, 0, len);
                }
                byte[] allData = baos.toByteArray();
                if (allData.length == 0) {
                  continue;
                }
                String fileDigest = Hex.encodeHexString(DigestUtils.sha(
                    allData));
                String ascii = new String(allData, "US-ASCII");
                BufferedReader br3 = new BufferedReader(new StringReader(
                    ascii));
                String firstLine = null;
                while ((firstLine = br3.readLine()) != null) {
                  if (firstLine.startsWith("@")) {
                    continue;
                  } else {
                    break;
                  }
                }
                if (firstLine == null) {
                  continue;
                }
                if (firstLine.startsWith("published ")
                    || firstLine.startsWith("flag-thresholds ")
                    || firstLine.startsWith("r ")) {
                  bdp.parse(allData, dateTime, authorityFingerprint);
                  parsedStatuses++;
                } else if (descriptorImportHistory.contains(fileDigest)) {
                  /* Skip server descriptors or extra-info descriptors if
                   * we parsed them before. */
                  skippedFiles++;
                  continue;
                } else {
                  int start = -1;
                  int sig = -1;
                  int end = -1;
                  String startToken = firstLine.startsWith("router ")
                      ? "router " : "extra-info ";
                  String sigToken = "\nrouter-signature\n";
                  String endToken = "\n-----END SIGNATURE-----\n";
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
                    System.arraycopy(allData, start, descBytes, 0,
                        end - start);
                    String descriptorDigest = Hex.encodeHexString(
                        DigestUtils.sha(descBytes));
                    if (!descriptorImportHistory.contains(
                        descriptorDigest)) {
                      bdp.parse(descBytes, dateTime, authorityFingerprint);
                      descriptorImportHistory.add(descriptorDigest);
                      if (firstLine.startsWith("router ")) {
                        parsedServerDescriptors++;
                      } else {
                        parsedExtraInfoDescriptors++;
                      }
                    } else {
                      if (firstLine.startsWith("router ")) {
                        skippedServerDescriptors++;
                      } else {
                        skippedExtraInfoDescriptors++;
                      }
                    }
                  }
                }
                descriptorImportHistory.add(fileDigest);
                parsedFiles++;
              }
              bis.close();
            }
            in.close();

            /* Let's give some memory back, or we'll run out of it. */
            System.gc();

            parsed.add(pop.getName());
            modified = true;
          } catch (IOException e) {
            logger.warn("Could not parse bridge snapshot "
                + pop.getName() + "!", e);
            continue;
          }
        }
      }
      logger.debug("Finished importing files in directory "
          + bridgeDirectoriesDir + "/.  In total, we parsed "
          + parsedFiles + " files (skipped " + skippedFiles
          + ") containing " + parsedStatuses + " statuses, "
          + parsedServerDescriptors + " server descriptors (skipped "
          + skippedServerDescriptors + "), and "
          + parsedExtraInfoDescriptors + " extra-info descriptors "
          + "(skipped " + skippedExtraInfoDescriptors + ").");
      if (!parsed.isEmpty() && modified) {
        logger.debug("Writing file " + pbdFile.getAbsolutePath() + "...");
        pbdFile.getParentFile().mkdirs();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(pbdFile))) {
          for (String f : parsed) {
            bw.append(f + "\n");
          }
          logger.debug("Finished writing file " + pbdFile.getAbsolutePath()
              + ".");
        } catch (IOException e) {
          logger.warn("Failed writing file "
              + pbdFile.getAbsolutePath() + "!", e);
        }
      }
    }
  }
}

