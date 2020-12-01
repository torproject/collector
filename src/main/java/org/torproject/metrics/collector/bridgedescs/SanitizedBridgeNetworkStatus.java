/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import org.torproject.metrics.collector.conf.Annotation;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.SortedMap;
import java.util.TreeMap;

public class SanitizedBridgeNetworkStatus extends SanitizedBridgeDescriptor {

  private static final Logger logger = LoggerFactory.getLogger(
      SanitizedBridgeNetworkStatus.class);

  private final String authorityFingerprint;

  SanitizedBridgeNetworkStatus(byte[] originalBytes,
      SensitivePartsSanitizer sensitivePartsSanitizer, String publicationTime,
      String authorityFingerprint) {
    super(originalBytes, sensitivePartsSanitizer);
    this.publishedString = publicationTime;
    this.authorityFingerprint = authorityFingerprint;
  }

  boolean sanitizeDescriptor() {

    if (this.sensitivePartsSanitizer.hasPersistenceProblemWithSecrets()) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return false;
    }

    /* Parse the given network status line by line. */
    boolean includesFingerprintLine = false;
    DescriptorBuilder scrubbed = new DescriptorBuilder();
    scrubbed.append(Annotation.Status.toString());
    SortedMap<String, String> scrubbedEntries = new TreeMap<>();
    StringBuilder publishedStringBuilder = new StringBuilder();
    scrubbed.append("published ").append(publishedStringBuilder).newLine();
    DescriptorBuilder header = new DescriptorBuilder();
    scrubbed.append(header);

    try {
      BufferedReader br = new BufferedReader(new StringReader(new String(
          this.originalBytes, StandardCharsets.US_ASCII)));
      String line;
      String mostRecentDescPublished = null;
      byte[] fingerprintBytes = null;
      String descPublicationTime = null;
      String hashedBridgeIdentityHex = null;
      DescriptorBuilder scrubbedEntry = new DescriptorBuilder();
      while ((line = br.readLine()) != null) {

        /* Use publication time from "published" line instead of the
         * file's last-modified time.  Don't copy over the line, because
         * we're going to write a "published" line below. */
        if (line.startsWith("published ")) {
          this.publishedString = line.substring("published ".length());

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
            return false;
          }
          header.append(line).newLine();
          includesFingerprintLine = true;

          /* r lines contain sensitive information that needs to be removed
           * or replaced. */
        } else if (line.startsWith("r ")) {

          /* Clear buffer from previously scrubbed lines. */
          if (scrubbedEntry.hasContent()) {
            scrubbedEntries.put(hashedBridgeIdentityHex,
                scrubbedEntry.toString());
            scrubbedEntry = new DescriptorBuilder();
          }

          /* Parse the relevant parts of this r line. */
          String[] parts = line.split(" ");
          if (parts.length < 9) {
            logger.warn("Illegal line '{}' in bridge network "
                + "status.  Skipping descriptor.", line);
            return false;
          }
          if (!Base64.isBase64(parts[2])) {
            logger.warn("Illegal base64 character in r line '{}'.  "
                + "Skipping descriptor.", parts[2]);
            return false;
          }
          fingerprintBytes = Base64.decodeBase64(parts[2] + "==");
          descPublicationTime = parts[4] + " " + parts[5];
          String address = parts[6];
          String orPort = parts[7];
          String dirPort = parts[8];

          /* Determine most recent descriptor publication time. */
          if (descPublicationTime.compareTo(this.publishedString) <= 0
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
          scrubbedEntry.append("r ").append(nickname).space()
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
            scrubbedEntry.append("a ").append(scrubbedOrAddress).newLine();
          } else {
            logger.warn("Invalid address in line '{}' "
                + "in bridge network status.  Skipping line!", line);
          }

          /* Nothing special about s, w, and p lines; just copy them. */
        } else if (line.startsWith("s ") || line.equals("s")
            || line.startsWith("w ") || line.equals("w")
            || line.startsWith("p ") || line.equals("p")) {
          scrubbedEntry.append(line).newLine();

          /* There should be nothing else but r, a, w, p, and s lines in the
           * network status.  If there is, we should probably learn before
           * writing anything to the sanitized descriptors. */
        } else {
          logger.debug("Unknown line '{}' in bridge "
              + "network status. Not writing to disk!", line);
          return false;
        }
      }
      br.close();
      if (scrubbedEntry.hasContent()) {
        scrubbedEntries.put(hashedBridgeIdentityHex, scrubbedEntry.toString());
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
            + "authority operator to check!", this.publishedString);
      } else if (formatter.parse(this.publishedString).getTime()
          - formatter.parse(mostRecentDescPublished).getTime()
          > 60L * 60L * 1000L) {
        logger.warn("The most recent descriptor in the bridge "
                + "network status published at {} was published at {} which is "
                + "more than 1 hour before the status. This is a sign for "
                + "the status being stale. Please check!",
            this.publishedString, mostRecentDescPublished);
      }
    } catch (ParseException e) {
      logger.warn("Could not parse timestamp in bridge network status.", e);
      return false;
    } catch (IOException e) {
      logger.warn("Could not parse bridge network status.", e);
      return false;
    }

    /* Write the sanitized network status to disk. */
    publishedStringBuilder.append(this.publishedString);
    for (String scrubbedEntry : scrubbedEntries.values()) {
      scrubbed.append(scrubbedEntry);
    }
    this.sanitizedBytes = scrubbed.toBytes();
    return true;
  }


  byte[] getSanitizedBytes() {
    return this.sanitizedBytes;
  }

  public String getPublishedString() {
    return this.publishedString;
  }
}

