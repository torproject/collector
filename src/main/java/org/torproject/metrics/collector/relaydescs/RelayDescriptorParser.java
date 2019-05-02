/* Copyright 2010--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.relaydescs;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;

/**
 * Parses relay descriptors including network status consensuses and
 * votes, server and extra-info descriptors, and passes the results to the
 * stats handlers, to the archive writer, or to the relay descriptor
 * downloader.
 */
public class RelayDescriptorParser {

  /**
   * File writer that writes descriptor contents to files in a
   * directory-archive directory structure.
   */
  private ArchiveWriter aw;

  private ArchiveReader ar;

  /**
   * Missing descriptor downloader that uses the parse results to learn
   * which descriptors we are missing and want to download.
   */
  private RelayDescriptorDownloader rdd;

  /**
   * Logger for this class.
   */
  private static final Logger logger = LoggerFactory.getLogger(
      RelayDescriptorParser.class);

  private SimpleDateFormat dateTimeFormat;

  /**
   * Initializes this class.
   */
  public RelayDescriptorParser(ArchiveWriter aw) {
    this.aw = aw;

    this.dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    this.dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  public void setRelayDescriptorDownloader(
      RelayDescriptorDownloader rdd) {
    this.rdd = rdd;
  }

  public void setArchiveReader(ArchiveReader ar) {
    this.ar = ar;
  }

  /** Parses the given bytes to find out the contained descriptor type,
   * forwards them to the archive writer to store them to disk, and tells
   * the relay descriptor downloader and archive reader about the
   * contained descriptor and all referenced descriptors. */
  public boolean parse(byte[] data) {
    boolean stored = false;
    try {
      /* Convert descriptor to ASCII for parsing. This means we'll lose
       * the non-ASCII chars, but we don't care about them for parsing
       * anyway. */
      BufferedReader br = new BufferedReader(new StringReader(new String(
          data, "US-ASCII")));
      String line;
      do {
        line = br.readLine();
      } while (line != null && line.startsWith("@"));
      if (line == null) {
        logger.debug("We were given an empty descriptor for "
            + "parsing. Ignoring.");
        return false;
      }
      SimpleDateFormat parseFormat =
          new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      parseFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      if (line.startsWith("network-status-version 3")) {
        String statusType = "consensus";
        if (line.equals("network-status-version 3 microdesc")) {
          statusType = "consensus-microdesc";
        }
        String validAfterTime = null;
        String fingerprint = null;
        String dirSource = null;
        long validAfter = -1L;
        long dirKeyPublished = -1L;
        SortedSet<String> dirSources = new TreeSet<>();
        SortedSet<String> serverDescriptors = new TreeSet<>();
        SortedSet<String> serverDescriptorDigests = new TreeSet<>();
        SortedSet<String> microdescriptorKeys = new TreeSet<>();
        SortedSet<String> microdescriptorDigests = new TreeSet<>();
        StringBuilder certificateStringBuilder = null;
        String certificateString = null;
        String lastRelayIdentity = null;
        while ((line = br.readLine()) != null) {
          if (certificateStringBuilder != null) {
            if (line.startsWith("r ")) {
              certificateString = certificateStringBuilder.toString();
              certificateStringBuilder = null;
            } else {
              certificateStringBuilder.append(line).append("\n");
            }
          }
          if (line.equals("vote-status vote")) {
            statusType = "vote";
          } else if (line.startsWith("valid-after ")) {
            validAfterTime = line.substring("valid-after ".length());
            validAfter = parseFormat.parse(validAfterTime).getTime();
          } else if (line.startsWith("dir-source ")) {
            dirSource = line.split(" ")[2];
          } else if (line.startsWith("vote-digest ")) {
            dirSources.add(dirSource);
          } else if (line.startsWith("dir-key-certificate-version ")) {
            certificateStringBuilder = new StringBuilder();
            certificateStringBuilder.append(line).append("\n");
          } else if (line.startsWith("fingerprint ")) {
            fingerprint = line.split(" ")[1];
          } else if (line.startsWith("dir-key-published ")) {
            String dirKeyPublishedTime = line.substring(
                "dir-key-published ".length());
            dirKeyPublished = parseFormat.parse(dirKeyPublishedTime)
                .getTime();
          } else if (line.startsWith("r ")) {
            String[] parts = line.split(" ");
            if (parts.length == 8) {
              lastRelayIdentity = Hex.encodeHexString(Base64.decodeBase64(
                  parts[2] + "=")).toLowerCase();
            } else if (parts.length == 9) {
              lastRelayIdentity = Hex.encodeHexString(Base64.decodeBase64(
                  parts[2] + "=")).toLowerCase();
              String serverDesc = Hex.encodeHexString(Base64.decodeBase64(
                  parts[3] + "=")).toLowerCase();
              String publishedTime = parts[4] + " " + parts[5];
              serverDescriptors.add(publishedTime + ","
                  + lastRelayIdentity + "," + serverDesc);
              serverDescriptorDigests.add(serverDesc);
            } else {
              logger.warn("Could not parse r line '{}' in descriptor. "
                  + "Skipping.", line);
              break;
            }
          } else if (line.startsWith("m ")) {
            String[] parts = line.split(" ");
            if (parts.length == 2 && parts[1].length() == 43) {
              String digest256Base64 = parts[1];
              microdescriptorKeys.add(validAfterTime + ","
                  + lastRelayIdentity + "," + digest256Base64);
              String digest256Hex = Hex.encodeHexString(
                  Base64.decodeBase64(digest256Base64 + "="))
                  .toLowerCase();
              microdescriptorDigests.add(digest256Hex);
            } else if (parts.length != 3
                || !parts[2].startsWith("sha256=")
                || parts[2].length() != 50) {
              logger.warn("Could not parse m line '{}' in descriptor. "
                  + "Skipping.", line);
              break;
            }
          }
        }
        switch (statusType) {
          case "consensus":
            if (this.rdd != null) {
              this.rdd.haveParsedConsensus(validAfterTime, dirSources,
                  serverDescriptors);
            }
            if (this.aw != null) {
              this.aw.storeConsensus(data, validAfter, dirSources,
                  serverDescriptorDigests);
              stored = true;
            }
            break;
          case "consensus-microdesc":
            if (this.rdd != null) {
              this.rdd.haveParsedMicrodescConsensus(validAfterTime,
                  microdescriptorKeys);
            }
            if (this.ar != null) {
              this.ar.haveParsedMicrodescConsensus(validAfterTime,
                  microdescriptorDigests);
            }
            if (this.aw != null) {
              this.aw.storeMicrodescConsensus(data, validAfter,
                  microdescriptorDigests);
              stored = true;
            }
            break;
          default:
            if (this.aw != null || this.rdd != null) {
              String ascii = new String(data, "US-ASCII");
              String startToken = "network-status-version ";
              String sigToken = "directory-signature ";
              int start = ascii.indexOf(startToken);
              int sig = ascii.indexOf(sigToken);
              if (start >= 0 && sig >= 0 && sig > start) {
                sig += sigToken.length();
                byte[] forDigest = new byte[sig - start];
                System.arraycopy(data, start, forDigest, 0, sig - start);
                String digest = DigestUtils.sha1Hex(forDigest).toUpperCase();
                if (this.aw != null) {
                  this.aw.storeVote(data, validAfter, dirSource, digest,
                      serverDescriptorDigests);
                  stored = true;
                }
                if (this.rdd != null) {
                  this.rdd.haveParsedVote(validAfterTime, fingerprint,
                      serverDescriptors);
                }
              }
              if (certificateString != null) {
                if (this.aw != null) {
                  this.aw.storeCertificate(certificateString.getBytes(),
                      dirSource, dirKeyPublished);
                  stored = true;
                }
              }
            }
            break;
        }
      } else if (line.startsWith("router ")) {
        String publishedTime = null;
        String extraInfoDigest = null;
        String relayIdentifier = null;
        long published = -1L;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("published ")) {
            publishedTime = line.substring("published ".length());
            published = parseFormat.parse(publishedTime).getTime();
          } else if (line.startsWith("opt fingerprint")
              || line.startsWith("fingerprint")) {
            relayIdentifier = line.substring(line.startsWith("opt ")
                ? "opt fingerprint".length() : "fingerprint".length())
                .replaceAll(" ", "").toLowerCase();
          } else if (line.startsWith("opt extra-info-digest ")
              || line.startsWith("extra-info-digest ")) {
            extraInfoDigest = line.startsWith("opt ")
                ? line.split(" ")[2].toLowerCase()
                : line.split(" ")[1].toLowerCase();
          }
        }
        String ascii = new String(data, "US-ASCII");
        String startToken = "router ";
        String sigToken = "\nrouter-signature\n";
        int start = ascii.indexOf(startToken);
        int sig = ascii.indexOf(sigToken) + sigToken.length();
        String digest = null;
        if (start >= 0 || sig >= 0 || sig > start) {
          byte[] forDigest = new byte[sig - start];
          System.arraycopy(data, start, forDigest, 0, sig - start);
          digest = DigestUtils.sha1Hex(forDigest);
        }
        if (this.aw != null && digest != null) {
          this.aw.storeServerDescriptor(data, digest, published,
              extraInfoDigest);
          stored = true;
        }
        if (this.rdd != null && digest != null) {
          this.rdd.haveParsedServerDescriptor(publishedTime,
              relayIdentifier, digest, extraInfoDigest);
        }
      } else if (line.startsWith("extra-info ")) {
        String publishedTime = null;
        String relayIdentifier = line.split(" ")[2];
        long published = -1L;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("published ")) {
            publishedTime = line.substring("published ".length());
            published = parseFormat.parse(publishedTime).getTime();
          }
        }
        String ascii = new String(data, "US-ASCII");
        String startToken = "extra-info ";
        String sigToken = "\nrouter-signature\n";
        String digest = null;
        int start = ascii.indexOf(startToken);
        if (start > 0) {
          /* Do not confuse "extra-info " in "@type extra-info 1.0" with
           * "extra-info 0000...".  TODO This is a hack that should be
           * solved by using metrics-lib some day. */
          start = ascii.indexOf("\n" + startToken);
          if (start > 0) {
            start++;
          }
        }
        int sig = ascii.indexOf(sigToken) + sigToken.length();
        if (start >= 0 && sig >= 0 && sig > start) {
          byte[] forDigest = new byte[sig - start];
          System.arraycopy(data, start, forDigest, 0, sig - start);
          digest = DigestUtils.sha1Hex(forDigest);
        }
        if (this.aw != null && digest != null) {
          this.aw.storeExtraInfoDescriptor(data, digest, published);
          stored = true;
        }
        if (this.rdd != null && digest != null) {
          this.rdd.haveParsedExtraInfoDescriptor(publishedTime,
              relayIdentifier.toLowerCase(), digest);
        }
      } else if (line.equals("onion-key")) {
        /* Cannot store microdescriptors without knowing valid-after
         * time(s) of microdesc consensuses containing them, because we
         * don't know which month directories to put them in.  Have to use
         * storeMicrodescriptor below. */
      } else if (line.matches("[0-9]{10}")) {
        /* The following code is a much more lenient version of the parser in
         * metrics-lib that we need for storing a bandwidth file even if
         * metrics-lib has trouble verifying its format. As in metrics-lib,
         * identifying bandwidth files by a 10-digit timestamp in the first line
         * breaks with files generated before 2002 or after 2286 and when the
         * next descriptor identifier starts with just a timestamp in the first
         * line rather than a document type identifier. */
        String timestampLine = line;
        LocalDateTime fileCreatedOrTimestamp = null;
        try {
          while ((line = br.readLine()) != null) {
            if (line.startsWith("file_created=")) {
              fileCreatedOrTimestamp = LocalDateTime.parse(
                  line.substring("file_created=".length()));
              break;
            } else if (line.startsWith("bw=") || line.contains(" bw=")
                || "====".equals(line) || "=====".equals(line)) {
              break;
            }
          }
        } catch (IOException | DateTimeParseException e) {
          /* Fall back to using timestamp in first line. */
        }
        if (null == fileCreatedOrTimestamp) {
          try {
            fileCreatedOrTimestamp = LocalDateTime.ofInstant(
                Instant.ofEpochSecond(Long.parseLong(timestampLine)),
                ZoneOffset.UTC);
          } catch (NumberFormatException | DateTimeParseException e) {
            logger.warn("Could not parse timestamp or file_created time from "
                + "bandwidth file. Storing with timestamp 2000-01-01 00:00:00");
            fileCreatedOrTimestamp = LocalDateTime.of(2000, 1, 1, 0, 0, 0);
          }
        }
        this.aw.storeBandwidthFile(data, fileCreatedOrTimestamp,
            DigestUtils.sha256Hex(data).toUpperCase());
        stored = true;
      }
      br.close();
    } catch (IOException | ParseException e) {
      logger.warn("Could not parse descriptor. "
          + "Skipping.", e);
    }
    return stored;
  }

  /** Forwards the given microdescriptor to the archive writer to store
   * it to disk and tells the relay descriptor downloader that this
   * microdescriptor is not missing anymore. */
  public void storeMicrodescriptor(byte[] data, String digest256Hex,
      String digest256Base64, long validAfter) {
    if (this.aw != null) {
      this.aw.storeMicrodescriptor(data, digest256Hex, validAfter);
    }
    if (this.rdd != null) {
      this.rdd.haveParsedMicrodescriptor(digest256Base64);
    }
  }
}

