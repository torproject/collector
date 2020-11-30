/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.metrics.collector.conf.Annotation;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.persist.PersistenceUtils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
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
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeMap;
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
  private static final String BRIDGE_DESCRIPTORS = "bridge-descriptors";

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

  private Path inputDirectory;

  private Path outputDirectory;

  private Path recentDirectory;

  private Path statsDirectory;

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

    this.outputDirectory = config.getPath(Key.OutputPath)
        .resolve(BRIDGE_DESCRIPTORS);
    this.recentDirectory = config.getPath(Key.RecentPath)
        .resolve(BRIDGE_DESCRIPTORS);
    this.inputDirectory = config.getPath(Key.BridgeLocalOrigins);
    this.statsDirectory = config.getPath(Key.StatsPath);
    boolean replaceIpAddressesWithHashes =
        config.getBool(Key.ReplaceIpAddressesWithHashes);
    SimpleDateFormat rsyncCatFormat = new SimpleDateFormat(
        "yyyy-MM-dd-HH-mm-ss");
    this.rsyncCatString = rsyncCatFormat.format(
        System.currentTimeMillis());

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
    this.readBridgeSnapshots(this.inputDirectory, this.statsDirectory);

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

  private String maxNetworkStatusPublishedTime = "1970-01-01 00:00:00";

  /**
   * Sanitizes a network status and writes it to disk.
   */
  public void sanitizeAndStoreNetworkStatus(byte[] data,
      String publicationTime, String authorityFingerprint) {

    if (this.sensitivePartsSanitizer.hasPersistenceProblemWithSecrets()) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return;
    }

    if (publicationTime.compareTo(maxNetworkStatusPublishedTime) > 0) {
      maxNetworkStatusPublishedTime = publicationTime;
    }

    /* Parse the given network status line by line. */
    DescriptorBuilder header = new DescriptorBuilder();
    boolean includesFingerprintLine = false;
    SortedMap<String, String> scrubbedLines = new TreeMap<>();
    try {
      DescriptorBuilder scrubbed = new DescriptorBuilder();
      BufferedReader br = new BufferedReader(new StringReader(new String(
          data, StandardCharsets.US_ASCII)));
      String line;
      String mostRecentDescPublished = null;
      byte[] fingerprintBytes = null;
      String descPublicationTime = null;
      String hashedBridgeIdentityHex = null;
      while ((line = br.readLine()) != null) {

        /* Use publication time from "published" line instead of the
         * file's last-modified time.  Don't copy over the line, because
         * we're going to write a "published" line below. */
        if (line.startsWith("published ")) {
          publicationTime = line.substring("published ".length());

        /* Additional header lines don't have to be cleaned up. */
        } else if (line.startsWith("flag-thresholds ")) {
          header.append(line).newLine();

        /* The authority fingerprint in the "fingerprint" line can go in
         * unscrubbed. */
        } else if (line.startsWith("fingerprint ")) {
          if (!("fingerprint " + authorityFingerprint).equals(line)) {
            logger.warn("Mismatch between authority fingerprint expected from "
                + "file name ({}) and parsed from \"fingerprint\" "
                + "line (\"{}\").", authorityFingerprint, line);
            return;
          }
          header.append(line).newLine();
          includesFingerprintLine = true;

        /* r lines contain sensitive information that needs to be removed
         * or replaced. */
        } else if (line.startsWith("r ")) {

          /* Clear buffer from previously scrubbed lines. */
          if (scrubbed.hasContent()) {
            String scrubbedLine = scrubbed.toString();
            scrubbedLines.put(hashedBridgeIdentityHex, scrubbedLine);
            scrubbed = new DescriptorBuilder();
          }

          /* Parse the relevant parts of this r line. */
          String[] parts = line.split(" ");
          if (parts.length < 9) {
            logger.warn("Illegal line '{}' in bridge network "
                + "status.  Skipping descriptor.", line);
            return;
          }
          if (!Base64.isBase64(parts[2])) {
            logger.warn("Illegal base64 character in r line '{}'.  "
                + "Skipping descriptor.", parts[2]);
            return;
          }
          fingerprintBytes = Base64.decodeBase64(parts[2] + "==");
          descPublicationTime = parts[4] + " " + parts[5];
          String address = parts[6];
          String orPort = parts[7];
          String dirPort = parts[8];

          /* Determine most recent descriptor publication time. */
          if (descPublicationTime.compareTo(publicationTime) <= 0
              && (mostRecentDescPublished == null
              || descPublicationTime.compareTo(
              mostRecentDescPublished) > 0)) {
            mostRecentDescPublished = descPublicationTime;
          }

          /* Write scrubbed r line to buffer. */
          byte[] hashedBridgeIdentity = DigestUtils.sha1(fingerprintBytes);
          String hashedBridgeIdentityBase64 = Base64.encodeBase64String(
              hashedBridgeIdentity).substring(0, 27);
          hashedBridgeIdentityHex = Hex.encodeHexString(
              hashedBridgeIdentity);
          String descriptorIdentifier = parts[3];
          String hashedDescriptorIdentifier = Base64.encodeBase64String(
              DigestUtils.sha1(Base64.decodeBase64(descriptorIdentifier
              + "=="))).substring(0, 27);
          String scrubbedAddress = this.sensitivePartsSanitizer
              .scrubIpv4Address(address, fingerprintBytes, descPublicationTime);
          String nickname = parts[1];
          String scrubbedOrPort = this.sensitivePartsSanitizer.scrubTcpPort(
              orPort, fingerprintBytes, descPublicationTime);
          String scrubbedDirPort = this.sensitivePartsSanitizer.scrubTcpPort(
              dirPort, fingerprintBytes, descPublicationTime);
          scrubbed.append("r ").append(nickname).space()
              .append(hashedBridgeIdentityBase64).space()
              .append(hashedDescriptorIdentifier).space()
              .append(descPublicationTime).space()
              .append(scrubbedAddress).space()
              .append(scrubbedOrPort).space()
              .append(scrubbedDirPort).newLine();

        /* Sanitize any addresses in a lines using the fingerprint and
         * descriptor publication time from the previous r line. */
        } else if (line.startsWith("a ")) {
          String scrubbedOrAddress = this.sensitivePartsSanitizer
              .scrubOrAddress(line.substring("a ".length()), fingerprintBytes,
              descPublicationTime);
          if (scrubbedOrAddress != null) {
            scrubbed.append("a ").append(scrubbedOrAddress).newLine();
          } else {
            logger.warn("Invalid address in line '{}' "
                + "in bridge network status.  Skipping line!", line);
          }

        /* Nothing special about s, w, and p lines; just copy them. */
        } else if (line.startsWith("s ") || line.equals("s")
            || line.startsWith("w ") || line.equals("w")
            || line.startsWith("p ") || line.equals("p")) {
          scrubbed.append(line).newLine();

        /* There should be nothing else but r, a, w, p, and s lines in the
         * network status.  If there is, we should probably learn before
         * writing anything to the sanitized descriptors. */
        } else {
          logger.debug("Unknown line '{}' in bridge "
              + "network status. Not writing to disk!", line);
          return;
        }
      }
      br.close();
      if (scrubbed.hasContent()) {
        String scrubbedLine = scrubbed.toString();
        scrubbedLines.put(hashedBridgeIdentityHex, scrubbedLine);
      }
      if (!includesFingerprintLine) {
        header.append("fingerprint ").append(authorityFingerprint).newLine();
      }

      /* Check if we can tell from the descriptor publication times
       * whether this status is possibly stale. */
      SimpleDateFormat formatter = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      if (null == mostRecentDescPublished) {
        logger.warn("The bridge network status published at {}"
            + " does not contain a single entry. Please ask the bridge "
            + "authority operator to check!", publicationTime);
      } else if (formatter.parse(publicationTime).getTime()
          - formatter.parse(mostRecentDescPublished).getTime()
          > 60L * 60L * 1000L) {
        logger.warn("The most recent descriptor in the bridge "
            + "network status published at {} was published at {} which is "
            + "more than 1 hour before the status. This is a sign for "
            + "the status being stale. Please check!",
            publicationTime, mostRecentDescPublished);
      }
    } catch (ParseException e) {
      logger.warn("Could not parse timestamp in bridge network status.", e);
      return;
    } catch (IOException e) {
      logger.warn("Could not parse bridge network status.", e);
      return;
    }

    /* Write the sanitized network status to disk. */
    try {
      String syear = publicationTime.substring(0, 4);
      String smonth = publicationTime.substring(5, 7);
      String sday = publicationTime.substring(8, 10);
      String stime = publicationTime.substring(11, 13)
          + publicationTime.substring(14, 16)
          + publicationTime.substring(17, 19);
      String fileName = syear + smonth + sday + "-" + stime + "-"
          + authorityFingerprint;
      Path tarballFile = this.outputDirectory.resolve(
          Paths.get(syear, smonth, "statuses", sday, fileName));
      Path rsyncFile = this.recentDirectory.resolve(
          Paths.get("statuses", fileName));
      Path[] outputFiles = new Path[] { tarballFile, rsyncFile };
      for (Path outputFile : outputFiles) {
        Files.createDirectories(outputFile.getParent());
        StringBuilder sanitizedStatus = new StringBuilder();
        sanitizedStatus.append(Annotation.Status.toString());
        sanitizedStatus.append("published ").append(publicationTime)
            .append("\n");
        sanitizedStatus.append(header.toString());
        for (String scrubbed : scrubbedLines.values()) {
          sanitizedStatus.append(scrubbed);
        }
        Files.write(outputFile, sanitizedStatus.toString().getBytes());
      }
    } catch (IOException e) {
      logger.warn("Could not write sanitized bridge "
          + "network status to disk.", e);
    }
  }

  private String maxServerDescriptorPublishedTime = "1970-01-01 00:00:00";

  /**
   * Sanitizes a bridge server descriptor and writes it to disk.
   */
  public void sanitizeAndStoreServerDescriptor(byte[] data) {

    if (this.sensitivePartsSanitizer.hasPersistenceProblemWithSecrets()) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return;
    }

    /* Parse descriptor to generate a sanitized version. */
    String address = null;
    String published = null;
    byte[] fingerprintBytes = null;
    StringBuilder scrubbedAddress = null;
    Map<StringBuilder, String> scrubbedTcpPorts = new HashMap<>();
    Map<StringBuilder, String> scrubbedIpAddressesAndTcpPorts = new HashMap<>();
    String masterKeyEd25519FromIdentityEd25519 = null;
    DescriptorBuilder scrubbed = new DescriptorBuilder();
    try (BufferedReader br = new BufferedReader(new StringReader(
        new String(data, StandardCharsets.US_ASCII)))) {
      scrubbed.append(Annotation.BridgeServer.toString());
      String line;
      String masterKeyEd25519 = null;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {

        /* Skip all crypto parts that might be used to derive the bridge's
         * identity fingerprint. */
        if (skipCrypto && !line.startsWith("-----END ")) {
          continue;

        /* Store the router line for later processing, because we may need
         * the bridge identity fingerprint for replacing the IP address in
         * the scrubbed version.  */
        } else if (line.startsWith("router ")) {
          String[] parts = line.split(" ");
          if (parts.length != 6) {
            logger.warn("Invalid router line: '{}'.  Skipping.", line);
            return;
          }
          address = parts[2];
          scrubbedAddress = new StringBuilder();
          StringBuilder scrubbedOrPort = new StringBuilder();
          scrubbedTcpPorts.put(scrubbedOrPort, parts[3]);
          StringBuilder scrubbedDirPort = new StringBuilder();
          scrubbedTcpPorts.put(scrubbedDirPort, parts[4]);
          StringBuilder scrubbedSocksPort = new StringBuilder();
          scrubbedTcpPorts.put(scrubbedSocksPort, parts[5]);
          scrubbed.append("router ").append(parts[1]).space()
              .append(scrubbedAddress).space()
              .append(scrubbedOrPort).space()
              .append(scrubbedDirPort).space()
              .append(scrubbedSocksPort).newLine();

        /* Store or-address and sanitize it when we have read the fingerprint
         * and descriptor publication time. */
        } else if (line.startsWith("or-address ")) {
          String orAddress = line.substring("or-address ".length());
          StringBuilder scrubbedOrAddress = new StringBuilder();
          scrubbedIpAddressesAndTcpPorts.put(scrubbedOrAddress, orAddress);
          scrubbed.append("or-address ").append(scrubbedOrAddress).newLine();

        /* Parse the publication time to see if we're still inside the
         * sanitizing interval. */
        } else if (line.startsWith("published ")) {
          published = line.substring("published ".length());
          if (published.compareTo(maxServerDescriptorPublishedTime) > 0) {
            maxServerDescriptorPublishedTime = published;
          }
          scrubbed.append(line).newLine();

        /* Parse the fingerprint to determine the hashed bridge
         * identity. */
        } else if (line.startsWith("opt fingerprint ")
            || line.startsWith("fingerprint ")) {
          String fingerprint = line.substring(line.startsWith("opt ")
              ? "opt fingerprint".length() : "fingerprint".length())
              .replaceAll(" ", "").toLowerCase();
          fingerprintBytes = Hex.decodeHex(fingerprint.toCharArray());
          String hashedBridgeIdentity = DigestUtils.sha1Hex(fingerprintBytes)
              .toLowerCase();
          scrubbed.append(line.startsWith("opt ") ? "opt " : "")
              .append("fingerprint");
          for (int i = 0; i < hashedBridgeIdentity.length() / 4; i++) {
            scrubbed.space().append(hashedBridgeIdentity.substring(4 * i,
                4 * (i + 1)).toUpperCase());
          }
          scrubbed.newLine();

        /* Replace the contact line (if present) with a generic one. */
        } else if (line.startsWith("contact ")) {
          scrubbed.append("contact somebody").newLine();

        /* When we reach the signature, we're done. Write the sanitized
         * descriptor to disk below. */
        } else if (line.startsWith("router-signature")) {
          break;

        /* Replace extra-info digest with the hashed digest of the
         * non-scrubbed descriptor. */
        } else if (line.startsWith("opt extra-info-digest ")
            || line.startsWith("extra-info-digest ")) {
          String[] parts = line.split(" ");
          if (line.startsWith("opt ")) {
            scrubbed.append("opt ");
            parts = line.substring(4).split(" ");
          }
          if (parts.length > 3) {
            logger.warn("extra-info-digest line contains more arguments than"
                + "expected: '{}'.  Skipping descriptor.", line);
            return;
          }
          scrubbed.append("extra-info-digest ").append(DigestUtils.sha1Hex(
              Hex.decodeHex(parts[1].toCharArray())).toUpperCase());
          if (parts.length > 2) {
            if (!Base64.isBase64(parts[2])) {
              logger.warn("Illegal base64 character in extra-info-digest line "
                  + "'{}'.  Skipping descriptor.", line);
              return;
            }
            scrubbed.space().append(Base64.encodeBase64String(
                DigestUtils.sha256(Base64.decodeBase64(parts[2])))
                .replaceAll("=", ""));
          }
          scrubbed.newLine();

        /* Possibly sanitize reject lines if they contain the bridge's own
         * IP address. */
        } else if (line.startsWith("reject ")) {
          if (address != null && line.startsWith("reject " + address)) {
            scrubbed.append("reject ").append(scrubbedAddress)
                .append(line.substring("reject ".length() + address.length()))
                .newLine();
          } else {
            scrubbed.append(line).newLine();
          }

        /* Extract master-key-ed25519 from identity-ed25519. */
        } else if (line.equals("identity-ed25519")) {
          StringBuilder sb = new StringBuilder();
          while ((line = br.readLine()) != null
              && !line.equals("-----END ED25519 CERT-----")) {
            if (line.equals("-----BEGIN ED25519 CERT-----")) {
              continue;
            }
            sb.append(line);
          }
          masterKeyEd25519FromIdentityEd25519 =
              this.parseMasterKeyEd25519FromIdentityEd25519(
              sb.toString());
          if (masterKeyEd25519FromIdentityEd25519 == null) {
            logger.warn("Could not parse master-key-ed25519 from "
                + "identity-ed25519.  Skipping descriptor.");
            return;
          }
          String sha256MasterKeyEd25519 = Base64.encodeBase64String(
              DigestUtils.sha256(Base64.decodeBase64(
              masterKeyEd25519FromIdentityEd25519 + "=")))
              .replaceAll("=", "");
          scrubbed.append("master-key-ed25519 ").append(sha256MasterKeyEd25519)
              .newLine();
          if (masterKeyEd25519 != null && !masterKeyEd25519.equals(
              masterKeyEd25519FromIdentityEd25519)) {
            logger.warn("Mismatch between identity-ed25519 and "
                + "master-key-ed25519.  Skipping.");
            return;
          }

        /* Verify that identity-ed25519 and master-key-ed25519 match. */
        } else if (line.startsWith("master-key-ed25519 ")) {
          masterKeyEd25519 = line.substring(line.indexOf(" ") + 1);
          if (masterKeyEd25519FromIdentityEd25519 != null
              && !masterKeyEd25519FromIdentityEd25519.equals(
              masterKeyEd25519)) {
            logger.warn("Mismatch between identity-ed25519 and "
                + "master-key-ed25519.  Skipping.");
            return;
          }

        /* Write the following lines unmodified to the sanitized
         * descriptor. */
        } else if (line.startsWith("accept ")
            || line.startsWith("platform ")
            || line.startsWith("opt protocols ")
            || line.startsWith("protocols ")
            || line.startsWith("proto ")
            || line.startsWith("uptime ")
            || line.startsWith("bandwidth ")
            || line.startsWith("opt hibernating ")
            || line.startsWith("hibernating ")
            || line.startsWith("ntor-onion-key ")
            || line.equals("opt hidden-service-dir")
            || line.equals("hidden-service-dir")
            || line.equals("opt caches-extra-info")
            || line.equals("caches-extra-info")
            || line.equals("opt allow-single-hop-exits")
            || line.equals("allow-single-hop-exits")
            || line.startsWith("ipv6-policy ")
            || line.equals("tunnelled-dir-server")
            || line.startsWith("bridge-distribution-request ")) {
          scrubbed.append(line).newLine();

        /* Replace node fingerprints in the family line with their hashes
         * and leave nicknames unchanged. */
        } else if (line.startsWith("family ")) {
          DescriptorBuilder familyLine = new DescriptorBuilder("family");
          for (String s : line.substring(7).split(" ")) {
            if (s.startsWith("$")) {
              familyLine.append(" $").append(DigestUtils.sha1Hex(Hex.decodeHex(
                  s.substring(1).toCharArray())).toUpperCase());
            } else {
              familyLine.space().append(s);
            }
          }
          scrubbed.append(familyLine.toString()).newLine();

        /* Skip the purpose line that the bridge authority adds to its
         * cached-descriptors file. */
        } else if (line.startsWith("@purpose ")) {
          continue;

        /* Skip all crypto parts that might leak the bridge's identity
         * fingerprint. */
        } else if (line.startsWith("-----BEGIN ")
            || line.equals("onion-key") || line.equals("signing-key")
            || line.equals("onion-key-crosscert")
            || line.startsWith("ntor-onion-key-crosscert ")) {
          skipCrypto = true;

        /* Stop skipping lines when the crypto parts are over. */
        } else if (line.startsWith("-----END ")) {
          skipCrypto = false;

        /* Skip the ed25519 signature; we'll include a SHA256 digest of
         * the SHA256 descriptor digest in router-digest-sha256. */
        } else if (line.startsWith("router-sig-ed25519 ")) {
          continue;

        /* If we encounter an unrecognized line, stop parsing and print
         * out a warning. We might have overlooked sensitive information
         * that we need to remove or replace for the sanitized descriptor
         * version. */
        } else {
          logger.warn("Unrecognized line '{}'. Skipping.", line);
          return;
        }
      }
    } catch (Exception e) {
      logger.warn("Could not parse server descriptor.", e);
      return;
    }

    /* Sanitize the parts that we couldn't sanitize earlier. */
    if (null == address || null == fingerprintBytes
        || null == published) {
      logger.warn("Missing either of the following lines that are "
          + "required to sanitize this server bridge descriptor: "
          + "\"router\", \"fingerprint\", \"published\". Skipping "
          + "descriptor.");
      return;
    }
    try {
      String scrubbedAddressString = this.sensitivePartsSanitizer
          .scrubIpv4Address(address, fingerprintBytes, published);
      if (null == scrubbedAddressString) {
        logger.warn("Invalid IP address in \"router\" line in bridge server "
            + "descriptor. Skipping descriptor.");
        return;
      }
      scrubbedAddress.append(scrubbedAddressString);
      for (Map.Entry<StringBuilder, String> e
          : scrubbedIpAddressesAndTcpPorts.entrySet()) {
        String scrubbedOrAddress = this.sensitivePartsSanitizer
            .scrubOrAddress(e.getValue(), fingerprintBytes, published);
        if (null == scrubbedOrAddress) {
          logger.warn("Invalid IP address or TCP port in \"or-address\" line "
              + "in bridge server descriptor. Skipping descriptor.");
          return;
        }
        e.getKey().append(scrubbedOrAddress);
      }
      for (Map.Entry<StringBuilder, String> e : scrubbedTcpPorts.entrySet()) {
        String scrubbedTcpPort = this.sensitivePartsSanitizer
            .scrubTcpPort(e.getValue(), fingerprintBytes, published);
        if (null == scrubbedTcpPort) {
          logger.warn("Invalid TCP port in \"router\" line in bridge server "
              + "descriptor. Skipping descriptor.");
          return;
        }
        e.getKey().append(scrubbedTcpPort);
      }
    } catch (IOException exception) {
      /* There's a persistence problem, so we shouldn't scrub more IP addresses
       * or TCP ports in this execution. */
      return;
    }

    /* Determine digest(s) of sanitized server descriptor. */
    String descriptorDigest = null;
    String ascii = new String(data, StandardCharsets.US_ASCII);
    String startToken = "router ";
    String sigToken = "\nrouter-signature\n";
    int start = ascii.indexOf(startToken);
    int sig = ascii.indexOf(sigToken) + sigToken.length();
    if (start >= 0 && sig >= 0 && sig > start) {
      byte[] forDigest = new byte[sig - start];
      System.arraycopy(data, start, forDigest, 0, sig - start);
      descriptorDigest = DigestUtils.sha1Hex(DigestUtils.sha1(forDigest));
    }
    if (descriptorDigest == null) {
      logger.warn("Could not calculate server descriptor digest.");
      return;
    }
    String descriptorDigestSha256Base64 = null;
    if (masterKeyEd25519FromIdentityEd25519 != null) {
      ascii = new String(data, StandardCharsets.US_ASCII);
      startToken = "router ";
      sigToken = "\n-----END SIGNATURE-----\n";
      start = ascii.indexOf(startToken);
      sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(data, start, forDigest, 0, sig - start);
        descriptorDigestSha256Base64 = Base64.encodeBase64String(
            DigestUtils.sha256(DigestUtils.sha256(forDigest)))
            .replaceAll("=", "");
      }
      if (descriptorDigestSha256Base64 == null) {
        logger.warn("Could not calculate server descriptor SHA256 digest.");
        return;
      }
    }
    if (null != descriptorDigestSha256Base64) {
      scrubbed.append("router-digest-sha256 ")
          .append(descriptorDigestSha256Base64).newLine();
    }
    scrubbed.append("router-digest ").append(descriptorDigest.toUpperCase())
        .newLine();

    /* Determine filename of sanitized server descriptor. */
    String dyear = published.substring(0, 4);
    String dmonth = published.substring(5, 7);
    try {
      Path tarballFile = this.outputDirectory.resolve(
          Paths.get(dyear, dmonth, "server-descriptors",
          descriptorDigest.substring(0, 1), descriptorDigest.substring(1, 2),
          descriptorDigest));
      Path rsyncCatFile = this.recentDirectory.resolve(
          Paths.get("bridge-descriptors", "server-descriptors",
          this.rsyncCatString + "-server-descriptors.tmp"));
      Path[] outputFiles = new Path[] { tarballFile, rsyncCatFile };
      boolean[] append = new boolean[] { false, true };
      for (int i = 0; i < outputFiles.length; i++) {
        Path outputFile = outputFiles[i];
        StandardOpenOption openOption = append[i] ? StandardOpenOption.APPEND
            : StandardOpenOption.CREATE_NEW;
        if (Files.exists(outputFile)
            && openOption != StandardOpenOption.APPEND) {
          /* We already stored this descriptor to disk before, so let's
           * not store it yet another time. */
          break;
        }
        Files.createDirectories(outputFile.getParent());
        Files.write(outputFile, scrubbed.toString().getBytes(), openOption);
      }
    } catch (IOException e) {
      logger.warn("Could not write sanitized server descriptor to disk.", e);
    }
  }

  private String parseMasterKeyEd25519FromIdentityEd25519(
      String identityEd25519Base64) {
    byte[] identityEd25519 = Base64.decodeBase64(identityEd25519Base64);
    if (identityEd25519.length < 40) {
      logger.warn("Invalid length of identity-ed25519 (in bytes): {}",
          identityEd25519.length);
    } else if (identityEd25519[0] != 0x01) {
      logger.warn("Unknown version in identity-ed25519: {}",
          identityEd25519[0]);
    } else if (identityEd25519[1] != 0x04) {
      logger.warn("Unknown cert type in identity-ed25519: {}",
          identityEd25519[1]);
    } else if (identityEd25519[6] != 0x01) {
      logger.warn("Unknown certified key type in identity-ed25519: {}",
          identityEd25519[1]);
    } else if (identityEd25519[39] == 0x00) {
      logger.warn("No extensions in identity-ed25519 (which "
          + "would contain the encoded master-key-ed25519): {}",
          identityEd25519[39]);
    } else {
      int extensionStart = 40;
      for (int i = 0; i < (int) identityEd25519[39]; i++) {
        if (identityEd25519.length < extensionStart + 4) {
          logger.warn("Invalid extension with id {} in identity-ed25519.", i);
          break;
        }
        int extensionLength = identityEd25519[extensionStart];
        extensionLength <<= 8;
        extensionLength += identityEd25519[extensionStart + 1];
        int extensionType = identityEd25519[extensionStart + 2];
        if (extensionLength == 32 && extensionType == 4) {
          if (identityEd25519.length < extensionStart + 4 + 32) {
            logger.warn("Invalid extension with id {} in identity-ed25519.", i);
            break;
          }
          byte[] masterKeyEd25519 = new byte[32];
          System.arraycopy(identityEd25519, extensionStart + 4,
              masterKeyEd25519, 0, masterKeyEd25519.length);
          String masterKeyEd25519Base64 = Base64.encodeBase64String(
              masterKeyEd25519);
          return masterKeyEd25519Base64.replaceAll("=", "");
        }
        extensionStart += 4 + extensionLength;
      }
    }
    logger.warn("Unable to locate master-key-ed25519 in identity-ed25519.");
    return null;
  }

  private String maxExtraInfoDescriptorPublishedTime =
      "1970-01-01 00:00:00";

  /**
   * Sanitizes an extra-info descriptor and writes it to disk.
   */
  public void sanitizeAndStoreExtraInfoDescriptor(byte[] data) {

    /* Parse descriptor to generate a sanitized version. */
    String published = null;
    String masterKeyEd25519FromIdentityEd25519 = null;
    DescriptorBuilder scrubbed = new DescriptorBuilder();
    try (BufferedReader br = new BufferedReader(new StringReader(new String(
          data, StandardCharsets.US_ASCII)))) {
      scrubbed.append(Annotation.BridgeExtraInfo.toString());
      String line;
      String hashedBridgeIdentity;
      String masterKeyEd25519 = null;
      while ((line = br.readLine()) != null) {

        /* Parse bridge identity from extra-info line and replace it with
         * its hash in the sanitized descriptor. */
        String[] parts = line.split(" ");
        if (line.startsWith("extra-info ")) {
          if (parts.length < 3) {
            logger.debug("Illegal line in extra-info descriptor: '{}'.  "
                + "Skipping descriptor.", line);
            return;
          }
          hashedBridgeIdentity = DigestUtils.sha1Hex(Hex.decodeHex(
              parts[2].toCharArray())).toLowerCase();
          scrubbed.append("extra-info ").append(parts[1])
            .space().append(hashedBridgeIdentity.toUpperCase()).newLine();

        /* Parse the publication time to determine the file name. */
        } else if (line.startsWith("published ")) {
          scrubbed.append(line).newLine();
          published = line.substring("published ".length());
          if (published.compareTo(maxExtraInfoDescriptorPublishedTime)
              > 0) {
            maxExtraInfoDescriptorPublishedTime = published;
          }

        /* Remove everything from transport lines except the transport
         * name. */
        } else if (line.startsWith("transport ")) {
          if (parts.length < 3) {
            logger.debug("Illegal line in extra-info descriptor: '{}'.  "
                + "Skipping descriptor.", line);
            return;
          }
          scrubbed.append("transport ").append(parts[1]).newLine();

        /* Skip transport-info lines entirely. */
        } else if (line.startsWith("transport-info ")) {

        /* Extract master-key-ed25519 from identity-ed25519. */
        } else if (line.equals("identity-ed25519")) {
          StringBuilder sb = new StringBuilder();
          while ((line = br.readLine()) != null
              && !line.equals("-----END ED25519 CERT-----")) {
            if (line.equals("-----BEGIN ED25519 CERT-----")) {
              continue;
            }
            sb.append(line);
          }
          masterKeyEd25519FromIdentityEd25519 =
              this.parseMasterKeyEd25519FromIdentityEd25519(
              sb.toString());
          String sha256MasterKeyEd25519 = Base64.encodeBase64String(
              DigestUtils.sha256(Base64.decodeBase64(
              masterKeyEd25519FromIdentityEd25519 + "=")))
              .replaceAll("=", "");
          scrubbed.append("master-key-ed25519 ").append(sha256MasterKeyEd25519)
              .newLine();
          if (masterKeyEd25519 != null && !masterKeyEd25519.equals(
              masterKeyEd25519FromIdentityEd25519)) {
            logger.warn("Mismatch between identity-ed25519 and "
                + "master-key-ed25519.  Skipping.");
            return;
          }

        /* Verify that identity-ed25519 and master-key-ed25519 match. */
        } else if (line.startsWith("master-key-ed25519 ")) {
          masterKeyEd25519 = line.substring(line.indexOf(" ") + 1);
          if (masterKeyEd25519FromIdentityEd25519 != null
              && !masterKeyEd25519FromIdentityEd25519.equals(
              masterKeyEd25519)) {
            logger.warn("Mismatch between identity-ed25519 and "
                + "master-key-ed25519.  Skipping.");
            return;
          }

        /* Write the following lines unmodified to the sanitized
         * descriptor. */
        } else if (line.startsWith("write-history ")
            || line.startsWith("read-history ")
            || line.startsWith("ipv6-write-history ")
            || line.startsWith("ipv6-read-history ")
            || line.startsWith("geoip-start-time ")
            || line.startsWith("geoip-client-origins ")
            || line.startsWith("geoip-db-digest ")
            || line.startsWith("geoip6-db-digest ")
            || line.startsWith("conn-bi-direct ")
            || line.startsWith("ipv6-conn-bi-direct ")
            || line.startsWith("bridge-")
            || line.startsWith("dirreq-")
            || line.startsWith("cell-")
            || line.startsWith("entry-")
            || line.startsWith("exit-")
            || line.startsWith("hidserv-")
            || line.startsWith("padding-counts ")) {
          scrubbed.append(line).newLine();

        /* When we reach the signature, we're done. Write the sanitized
         * descriptor to disk below. */
        } else if (line.startsWith("router-signature")) {
          break;

        /* Skip the ed25519 signature; we'll include a SHA256 digest of
         * the SHA256 descriptor digest in router-digest-sha256. */
        } else if (line.startsWith("router-sig-ed25519 ")) {
          continue;

        /* If we encounter an unrecognized line, stop parsing and print
         * out a warning. We might have overlooked sensitive information
         * that we need to remove or replace for the sanitized descriptor
         * version. */
        } else {
          logger.warn("Unrecognized line '{}'. Skipping.", line);
          return;
        }
      }
      br.close();
    } catch (DecoderException | IOException e) {
      logger.warn("Could not parse extra-info descriptor.", e);
      return;
    }

    /* Determine filename of sanitized extra-info descriptor. */
    String descriptorDigest = null;
    String ascii = new String(data, StandardCharsets.US_ASCII);
    String startToken = "extra-info ";
    String sigToken = "\nrouter-signature\n";
    int start = ascii.indexOf(startToken);
    int sig = ascii.indexOf(sigToken) + sigToken.length();
    if (start >= 0 && sig >= 0 && sig > start) {
      byte[] forDigest = new byte[sig - start];
      System.arraycopy(data, start, forDigest, 0, sig - start);
      descriptorDigest = DigestUtils.sha1Hex(DigestUtils.sha1(forDigest));
    }
    if (descriptorDigest == null) {
      logger.warn("Could not calculate extra-info descriptor digest.");
      return;
    }
    String descriptorDigestSha256Base64 = null;
    if (masterKeyEd25519FromIdentityEd25519 != null) {
      ascii = new String(data, StandardCharsets.US_ASCII);
      startToken = "extra-info ";
      sigToken = "\n-----END SIGNATURE-----\n";
      start = ascii.indexOf(startToken);
      sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(data, start, forDigest, 0, sig - start);
        descriptorDigestSha256Base64 = Base64.encodeBase64String(
            DigestUtils.sha256(DigestUtils.sha256(forDigest)))
            .replaceAll("=", "");
      }
      if (descriptorDigestSha256Base64 == null) {
        logger.warn("Could not calculate extra-info "
            + "descriptor SHA256 digest.");
        return;
      }
    }
    if (descriptorDigestSha256Base64 != null) {
      scrubbed.append("router-digest-sha256 ")
          .append(descriptorDigestSha256Base64).newLine();
    }
    scrubbed.append("router-digest ").append(descriptorDigest.toUpperCase())
        .newLine();

    /* Determine filename of sanitized extra-info descriptor. */
    String dyear = published.substring(0, 4);
    String dmonth = published.substring(5, 7);

    try {
      Path tarballFile = this.outputDirectory.resolve(
          Paths.get(dyear, dmonth, "extra-infos",
          descriptorDigest.substring(0, 1), descriptorDigest.substring(1, 2),
          descriptorDigest));
      Path rsyncCatFile = this.recentDirectory.resolve(
          Paths.get("bridge-descriptors", "extra-infos",
          this.rsyncCatString + "-extra-infos.tmp"));
      Path[] outputFiles = new Path[] { tarballFile, rsyncCatFile };
      boolean[] append = new boolean[] { false, true };
      for (int i = 0; i < outputFiles.length; i++) {
        Path outputFile = outputFiles[i];
        StandardOpenOption openOption = append[i] ? StandardOpenOption.APPEND
            : StandardOpenOption.CREATE_NEW;
        if (Files.exists(outputFile)
            && openOption != StandardOpenOption.APPEND) {
          /* We already stored this descriptor to disk before, so let's
           * not store it yet another time. */
          break;
        }
        Files.createDirectories(outputFile.getParent());
        Files.write(outputFile, scrubbed.toString().getBytes(), openOption);
      }
    } catch (IOException e) {
      logger.warn("Could not write sanitized extra-info descriptor to disk.",
          e);
    }
  }

  private void checkStaleDescriptors() {
    SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    long tooOldMillis = System.currentTimeMillis() - 330L * 60L * 1000L;
    try {
      long maxNetworkStatusPublishedMillis =
          dateTimeFormat.parse(maxNetworkStatusPublishedTime).getTime();
      if (maxNetworkStatusPublishedMillis > 0L
          && maxNetworkStatusPublishedMillis < tooOldMillis) {
        logger.warn("The last known bridge network status was "
            + "published {}, which is more than 5:30 hours in the past.",
            maxNetworkStatusPublishedTime);
      }
      long maxServerDescriptorPublishedMillis =
          dateTimeFormat.parse(maxServerDescriptorPublishedTime)
          .getTime();
      if (maxServerDescriptorPublishedMillis > 0L
          && maxServerDescriptorPublishedMillis < tooOldMillis) {
        logger.warn("The last known bridge server descriptor was "
            + "published {}, which is more than 5:30 hours in the past.",
            maxServerDescriptorPublishedTime);
      }
      long maxExtraInfoDescriptorPublishedMillis =
          dateTimeFormat.parse(maxExtraInfoDescriptorPublishedTime)
          .getTime();
      if (maxExtraInfoDescriptorPublishedMillis > 0L
          && maxExtraInfoDescriptorPublishedMillis < tooOldMillis) {
        logger.warn("The last known bridge extra-info descriptor "
            + "was published {}, which is more than 5:30 hours in the past.",
            maxExtraInfoDescriptorPublishedTime);
      }
    } catch (ParseException e) {
      logger.warn("Unable to parse timestamp for stale check.", e);
    }
  }

  /**
   * Delete all files from the rsync (out) directory that have not been modified
   * in the last three days (seven weeks), and remove the .tmp extension from
   * newly written files. */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(this.recentDirectory,
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(this.outputDirectory,
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}

