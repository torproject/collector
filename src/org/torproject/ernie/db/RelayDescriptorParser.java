/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

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

  /**
   * Missing descriptor downloader that uses the parse results to learn
   * which descriptors we are missing and want to download.
   */
  private RelayDescriptorDownloader rdd;

  /**
   * Logger for this class.
   */
  private Logger logger;

  private SimpleDateFormat dateTimeFormat;

  /**
   * Initializes this class.
   */
  public RelayDescriptorParser(ArchiveWriter aw) {
    this.aw = aw;

    /* Initialize logger. */
    this.logger = Logger.getLogger(RelayDescriptorParser.class.getName());

    this.dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    this.dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  public void setRelayDescriptorDownloader(
      RelayDescriptorDownloader rdd) {
    this.rdd = rdd;
  }

  public void parse(byte[] data) {
    try {
      /* Convert descriptor to ASCII for parsing. This means we'll lose
       * the non-ASCII chars, but we don't care about them for parsing
       * anyway. */
      BufferedReader br = new BufferedReader(new StringReader(new String(
          data, "US-ASCII")));
      String line = br.readLine();
      if (line == null) {
        this.logger.fine("We were given an empty descriptor for "
            + "parsing. Ignoring.");
        return;
      }
      SimpleDateFormat parseFormat =
          new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      parseFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      if (line.equals("network-status-version 3")) {
        // TODO when parsing the current consensus, check the fresh-until
        // time to see when we switch from hourly to half-hourly
        // consensuses
        boolean isConsensus = true;
        String validAfterTime = null, fingerprint = null,
            dirSource = null;
        long validAfter = -1L, dirKeyPublished = -1L;
        SortedSet<String> dirSources = new TreeSet<String>();
        SortedSet<String> serverDescriptors = new TreeSet<String>();
        SortedSet<String> hashedRelayIdentities = new TreeSet<String>();
        StringBuilder certificateStringBuilder = null;
        String certificateString = null;
        while ((line = br.readLine()) != null) {
          if (certificateStringBuilder != null) {
            if (line.startsWith("r ")) {
              certificateString = certificateStringBuilder.toString();
              certificateStringBuilder = null;
            } else {
              certificateStringBuilder.append(line + "\n");
            }
          }
          if (line.equals("vote-status vote")) {
            isConsensus = false;
          } else if (line.startsWith("valid-after ")) {
            validAfterTime = line.substring("valid-after ".length());
            validAfter = parseFormat.parse(validAfterTime).getTime();
          } else if (line.startsWith("dir-source ")) {
            dirSource = line.split(" ")[2];
          } else if (line.startsWith("vote-digest ")) {
            dirSources.add(dirSource);
          } else if (line.startsWith("dir-key-certificate-version ")) {
            certificateStringBuilder = new StringBuilder();
            certificateStringBuilder.append(line + "\n");
          } else if (line.startsWith("fingerprint ")) {
            fingerprint = line.split(" ")[1];
          } else if (line.startsWith("dir-key-published ")) {
            String dirKeyPublishedTime = line.substring(
                "dir-key-published ".length());
            dirKeyPublished = parseFormat.parse(dirKeyPublishedTime).
                getTime();
          } else if (line.startsWith("r ")) {
            String[] parts = line.split(" ");
            if (parts.length < 9) {
              this.logger.log(Level.WARNING, "Could not parse r line '"
                  + line + "' in descriptor. Skipping.");
              break;
            }
            String publishedTime = parts[4] + " " + parts[5];
            String relayIdentity = Hex.encodeHexString(
                Base64.decodeBase64(parts[2] + "=")).
                toLowerCase();
            String serverDesc = Hex.encodeHexString(Base64.decodeBase64(
                parts[3] + "=")).toLowerCase();
            serverDescriptors.add(publishedTime + "," + relayIdentity
                + "," + serverDesc);
            hashedRelayIdentities.add(DigestUtils.shaHex(
                Base64.decodeBase64(parts[2] + "=")).
                toUpperCase());
          }
        }
        if (isConsensus) {
          if (this.rdd != null) {
            this.rdd.haveParsedConsensus(validAfterTime, dirSources,
                serverDescriptors);
          }
          if (this.aw != null) {
            this.aw.storeConsensus(data, validAfter);
          }
        } else {
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
              String digest = DigestUtils.shaHex(forDigest).toUpperCase();
              if (this.aw != null) {
                this.aw.storeVote(data, validAfter, dirSource, digest);
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
              }
            }
          }
        }
      } else if (line.startsWith("router ")) {
        String publishedTime = null, extraInfoDigest = null,
            relayIdentifier = null;
        long published = -1L;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("published ")) {
            publishedTime = line.substring("published ".length());
            published = parseFormat.parse(publishedTime).getTime();
          } else if (line.startsWith("opt fingerprint") ||
              line.startsWith("fingerprint")) {
            relayIdentifier = line.substring(line.startsWith("opt ") ?
                "opt fingerprint".length() : "fingerprint".length()).
                replaceAll(" ", "").toLowerCase();
          } else if (line.startsWith("opt extra-info-digest ") ||
              line.startsWith("extra-info-digest ")) {
            extraInfoDigest = line.startsWith("opt ") ?
                line.split(" ")[2].toLowerCase() :
                line.split(" ")[1].toLowerCase();
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
          digest = DigestUtils.shaHex(forDigest);
        }
        if (this.aw != null && digest != null) {
          this.aw.storeServerDescriptor(data, digest, published);
        }
        if (this.rdd != null && digest != null) {
          this.rdd.haveParsedServerDescriptor(publishedTime,
              relayIdentifier, digest, extraInfoDigest);
        }
      } else if (line.startsWith("extra-info ")) {
        String publishedTime = null, relayIdentifier = line.split(" ")[2];
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
        int sig = ascii.indexOf(sigToken) + sigToken.length();
        if (start >= 0 || sig >= 0 || sig > start) {
          byte[] forDigest = new byte[sig - start];
          System.arraycopy(data, start, forDigest, 0, sig - start);
          digest = DigestUtils.shaHex(forDigest);
        }
        if (this.aw != null && digest != null) {
          this.aw.storeExtraInfoDescriptor(data, digest, published);
        }
        if (this.rdd != null && digest != null) {
          this.rdd.haveParsedExtraInfoDescriptor(publishedTime,
              relayIdentifier.toLowerCase(), digest);
        }
      }
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not parse descriptor. "
          + "Skipping.", e);
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not parse descriptor. "
          + "Skipping.", e);
    }
  }
}

