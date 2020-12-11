/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.persist.BridgeExtraInfoDescriptorPersistence;
import org.torproject.metrics.collector.persist.BridgeNetworkStatusPersistence;
import org.torproject.metrics.collector.persist.BridgeServerDescriptorPersistence;
import org.torproject.metrics.collector.persist.PersistenceUtils;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeSet;

/**
 * <p>Sanitizes bridge descriptors, i.e., removes all possibly sensitive
 * information from them, and writes them to a local directory structure.
 * During the sanitizing process, all information about the bridge
 * identity or IP address are removed or replaced. The goal is to keep the
 * sanitized bridge descriptors useful for statistical analysis while not
 * making it easier for an adversary to enumerate bridges.</p>
 *
 * <p>There are three types of bridge descriptors: bridge network statuses
 * (lists of all bridges at a given time), server descriptors (published
 * by the bridge to advertise their capabilities), and extra-info
 * descriptors (published by the bridge, mainly for statistical analysis).</p>
 */
public class SanitizedBridgesWriter extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      SanitizedBridgesWriter.class);

  /** Initialize configuration. */
  public SanitizedBridgesWriter(Configuration config) {
    super(config);
    this.mapPathDescriptors.put("recent/bridge-descriptors/statuses",
        BridgeNetworkStatus.class);
    this.mapPathDescriptors.put("recent/bridge-descriptors/server-descriptors",
        BridgeServerDescriptor.class);
    this.mapPathDescriptors.put("recent/bridge-descriptors/extra-infos",
        BridgeExtraInfoDescriptor.class);
  }

  private String rsyncCatString;

  private Path outputDirectory;

  private Path recentDirectory;

  private SensitivePartsSanitizer sensitivePartsSanitizer;

  @Override
  public String module() {
    return "bridgedescs";
  }

  @Override
  protected String syncMarker() {
    return "Bridge";
  }

  @Override
  protected void startProcessing() throws ConfigurationException {

    this.outputDirectory = config.getPath(Key.OutputPath);
    this.recentDirectory = config.getPath(Key.RecentPath);
    Path inputDirectory = config.getPath(Key.BridgeLocalOrigins);
    Path statsDirectory = config.getPath(Key.StatsPath);
    boolean replaceIpAddressesWithHashes =
        config.getBool(Key.ReplaceIpAddressesWithHashes);
    DateTimeFormatter rsyncCatFormat = DateTimeFormatter.ofPattern(
        "uuuu-MM-dd-HH-mm-ss");
    this.rsyncCatString = LocalDateTime.now().format(rsyncCatFormat);

    Path bridgeIpSecretsFile = statsDirectory.resolve("bridge-ip-secrets");
    if (replaceIpAddressesWithHashes) {
      long limitBridgeSanitizingIntervalDays
          = config.getInt(Key.BridgeDescriptorMappingsLimit);
      this.sensitivePartsSanitizer = new SensitivePartsSanitizer(
          bridgeIpSecretsFile, limitBridgeSanitizingIntervalDays);
    } else {
      this.sensitivePartsSanitizer = new SensitivePartsSanitizer();
    }

    // Import bridge descriptors
    this.readBridgeSnapshots(inputDirectory, statsDirectory);

    // Finish writing sanitized bridge descriptors to disk
    if (replaceIpAddressesWithHashes) {
      this.sensitivePartsSanitizer.finishWriting();
    }

    this.checkStaleDescriptors();

    this.cleanUpDirectories();
  }

  private void readBridgeSnapshots(Path bridgeDirectoriesDir,
      Path statsDirectory) {

    if (bridgeDirectoriesDir == null
        || statsDirectory == null) {
      throw new IllegalArgumentException();
    }

    SortedSet<String> parsed = new TreeSet<>();
    Path pbdFile = statsDirectory.resolve("parsed-bridge-directories");
    boolean modified = false;
    if (Files.exists(bridgeDirectoriesDir)) {
      if (Files.exists(pbdFile)) {
        logger.debug("Reading file {}...", pbdFile);
        try {
          parsed.addAll(Files.readAllLines(pbdFile));
          logger.debug("Finished reading file {}.", pbdFile);
        } catch (IOException e) {
          logger.warn("Failed reading file {}!", pbdFile, e);
          return;
        }
      }
      logger.debug("Importing files in directory {}/...", bridgeDirectoriesDir);
      Set<String> descriptorImportHistory = new HashSet<>();
      int parsedFiles = 0;
      int skippedFiles = 0;
      int parsedStatuses = 0;
      int parsedServerDescriptors = 0;
      int skippedServerDescriptors = 0;
      int parsedExtraInfoDescriptors = 0;
      int skippedExtraInfoDescriptors = 0;
      Stack<Path> filesInInputDir = new Stack<>();
      filesInInputDir.add(bridgeDirectoriesDir);
      while (!filesInInputDir.isEmpty()) {
        Path pop = filesInInputDir.pop();
        String fn = pop.getFileName().toString();
        if (Files.isDirectory(pop)) {
          try {
            Files.list(pop).forEachOrdered(filesInInputDir::add);
          } catch (IOException e) {
            e.printStackTrace();
          }
        } else if (!parsed.contains(pop.getFileName().toString())) {
          try (InputStream in = Files.newInputStream(pop)) {
            if (in.available() > 0) {
              TarArchiveInputStream tais;
              if (fn.endsWith(".tar.gz")) {
                GzipCompressorInputStream gcis =
                    new GzipCompressorInputStream(in);
                tais = new TarArchiveInputStream(gcis);
              } else if (fn.endsWith(".tar")) {
                tais = new TarArchiveInputStream(in);
              } else {
                continue;
              }
              BufferedInputStream bis = new BufferedInputStream(tais);
              String[] fnParts = fn.split("-");
              if (fnParts.length != 5) {
                logger.warn("Invalid bridge descriptor tarball file name: {}. "
                    + "Skipping.", fn);
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
                case "from-serge-":
                  authorityFingerprint =
                      "BA44A889E64B93FAA2B114E02C2A279A8555C533";
                  break;
                default:
                  logger.warn("Did not recognize the bridge authority that "
                      + "generated {}. Skipping.", fn);
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
                String fileDigest = Hex.encodeHexString(DigestUtils.sha1(
                    allData));
                String ascii = new String(allData, StandardCharsets.US_ASCII);
                BufferedReader br3 = new BufferedReader(new StringReader(
                    ascii));
                String firstLine;
                do {
                  firstLine = br3.readLine();
                } while (firstLine != null && firstLine.startsWith("@"));
                if (firstLine == null) {
                  continue;
                }
                if (firstLine.startsWith("published ")
                    || firstLine.startsWith("flag-thresholds ")
                    || firstLine.startsWith("r ")) {
                  this.sanitizeAndStoreNetworkStatus(allData, dateTime,
                      authorityFingerprint);
                  parsedStatuses++;
                } else if (descriptorImportHistory.contains(fileDigest)) {
                  /* Skip server descriptors or extra-info descriptors if
                   * we parsed them before. */
                  skippedFiles++;
                  continue;
                } else {
                  int start;
                  int sig;
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
                        DigestUtils.sha1(descBytes));
                    if (!descriptorImportHistory.contains(
                        descriptorDigest)) {
                      descriptorImportHistory.add(descriptorDigest);
                      if (firstLine.startsWith("router ")) {
                        this.sanitizeAndStoreServerDescriptor(descBytes);
                        parsedServerDescriptors++;
                      } else {
                        this.sanitizeAndStoreExtraInfoDescriptor(descBytes);
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

            /* Let's give some memory back, or we'll run out of it. */
            System.gc();

            parsed.add(fn);
            modified = true;
          } catch (IOException e) {
            logger.warn("Could not parse bridge snapshot {}!", pop, e);
          }
        }
      }
      logger.debug("Finished importing files in directory {}/. In total, we "
          + "parsed {} files (skipped {}) containing {} statuses, {} server "
          + "descriptors (skipped {}), and {} extra-info descriptors (skipped "
          + "{}).", bridgeDirectoriesDir, parsedFiles, skippedFiles,
          parsedStatuses, parsedServerDescriptors, skippedServerDescriptors,
          parsedExtraInfoDescriptors, skippedExtraInfoDescriptors);
      if (!parsed.isEmpty() && modified) {
        logger.debug("Writing file {}...", pbdFile);
        try {
          Files.createDirectories(pbdFile.getParent());
          Files.write(pbdFile, parsed);
          logger.debug("Finished writing file {}.", pbdFile);
        } catch (IOException e) {
          logger.warn("Failed writing file {}!", pbdFile, e);
        }
      }
    }
  }

  private String maxNetworkStatusPublishedTime = null;

  /**
   * Sanitizes a network status and writes it to disk.
   */
  public void sanitizeAndStoreNetworkStatus(byte[] data,
      String publicationTime, String authorityFingerprint) {

    SanitizedBridgeNetworkStatus sanitizedBridgeNetworkStatus
        = new SanitizedBridgeNetworkStatus(data, this.sensitivePartsSanitizer,
        publicationTime, authorityFingerprint);
    if (!sanitizedBridgeNetworkStatus.sanitizeDescriptor()) {
      logger.warn("Unable to sanitize bridge network status.");
      return;
    }
    byte[] scrubbedBytes = sanitizedBridgeNetworkStatus.getSanitizedBytes();
    publicationTime = sanitizedBridgeNetworkStatus.getPublishedString();
    if (null == maxNetworkStatusPublishedTime
        || publicationTime.compareTo(maxNetworkStatusPublishedTime) > 0) {
      maxNetworkStatusPublishedTime = publicationTime;
    }
    new BridgeNetworkStatusPersistence(scrubbedBytes, publicationTime,
        authorityFingerprint)
        .storeAll(this.recentDirectory, this.outputDirectory);
  }

  private String maxServerDescriptorPublishedTime = null;

  /**
   * Sanitizes a bridge server descriptor and writes it to disk.
   */
  public void sanitizeAndStoreServerDescriptor(byte[] data) {

    SanitizedBridgeServerDescriptor sanitizedBridgeServerDescriptor
        = new SanitizedBridgeServerDescriptor(data,
        this.sensitivePartsSanitizer);
    if (!sanitizedBridgeServerDescriptor.sanitizeDescriptor()) {
      logger.warn("Unable to sanitize bridge server descriptor.");
      return;
    }
    byte[] scrubbedBytes
        = sanitizedBridgeServerDescriptor.getSanitizedBytes();
    String published = sanitizedBridgeServerDescriptor.getPublishedString();
    if (null == maxServerDescriptorPublishedTime
        || published.compareTo(maxServerDescriptorPublishedTime) > 0) {
      maxServerDescriptorPublishedTime = published;
    }
    String descriptorDigest
        = sanitizedBridgeServerDescriptor.getDescriptorDigest();
    new BridgeServerDescriptorPersistence(scrubbedBytes, published,
        this.rsyncCatString, descriptorDigest)
        .storeAll(this.recentDirectory, this.outputDirectory);
  }

  private String maxExtraInfoDescriptorPublishedTime = null;

  /**
   * Sanitizes an extra-info descriptor and writes it to disk.
   */
  public void sanitizeAndStoreExtraInfoDescriptor(byte[] data) {

    SanitizedBridgeExtraInfoDescriptor sanitizedBridgeExtraInfoDescriptor
        = new SanitizedBridgeExtraInfoDescriptor(data,
        this.sensitivePartsSanitizer);
    if (!sanitizedBridgeExtraInfoDescriptor.sanitizeDescriptor()) {
      logger.warn("Unable to sanitize bridge extra-info descriptor.");
      return;
    }
    byte[] scrubbedBytes
        = sanitizedBridgeExtraInfoDescriptor.getSanitizedBytes();
    String published = sanitizedBridgeExtraInfoDescriptor.getPublishedString();
    if (null == maxExtraInfoDescriptorPublishedTime
        || published.compareTo(maxExtraInfoDescriptorPublishedTime) > 0) {
      maxExtraInfoDescriptorPublishedTime = published;
    }
    String descriptorDigest
        = sanitizedBridgeExtraInfoDescriptor.getDescriptorDigest();
    new BridgeExtraInfoDescriptorPersistence(scrubbedBytes, published,
        this.rsyncCatString, descriptorDigest)
        .storeAll(this.recentDirectory, this.outputDirectory);
  }

  private void checkStaleDescriptors() {
    DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern(
        "uuuu-MM-dd HH:mm:ss");
    LocalDateTime tooOld = LocalDateTime.now().minusMinutes(330L);
    if (null != maxNetworkStatusPublishedTime) {
      LocalDateTime maxNetworkStatusPublished = LocalDateTime.parse(
          maxNetworkStatusPublishedTime, dateTimeFormat);
      if (maxNetworkStatusPublished.isBefore(tooOld)) {
        logger.warn("The last known bridge network status was "
            + "published {}, which is more than 5:30 hours in the past.",
            maxNetworkStatusPublishedTime);
      }
    }
    if (null != maxServerDescriptorPublishedTime) {
      LocalDateTime maxServerDescriptorPublished = LocalDateTime.parse(
          maxServerDescriptorPublishedTime, dateTimeFormat);
      if (maxServerDescriptorPublished.isBefore(tooOld)) {
        logger.warn("The last known bridge server descriptor was "
            + "published {}, which is more than 5:30 hours in the past.",
            maxServerDescriptorPublishedTime);
      }
    }
    if (null != maxExtraInfoDescriptorPublishedTime) {
      LocalDateTime maxExtraInfoDescriptorPublished = LocalDateTime.parse(
          maxExtraInfoDescriptorPublishedTime, dateTimeFormat);
      if (maxExtraInfoDescriptorPublished.isBefore(tooOld)) {
        logger.warn("The last known bridge extra-info descriptor "
            + "was published {}, which is more than 5:30 hours in the past.",
            maxExtraInfoDescriptorPublishedTime);
      }
    }
  }

  /**
   * Delete all files from the rsync (out) directory that have not been modified
   * in the last three days (seven weeks), and remove the .tmp extension from
   * newly written files. */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(
        this.recentDirectory.resolve("bridge-descriptors"),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(
        this.outputDirectory.resolve("bridge-descriptors"),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}

