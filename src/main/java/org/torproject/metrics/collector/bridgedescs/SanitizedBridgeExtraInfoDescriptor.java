/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import org.torproject.metrics.collector.conf.Annotation;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

public class SanitizedBridgeExtraInfoDescriptor
    extends SanitizedBridgeDescriptor {

  private static final Logger logger = LoggerFactory.getLogger(
      SanitizedBridgeExtraInfoDescriptor.class);

  private String descriptorDigest;

  SanitizedBridgeExtraInfoDescriptor(byte[] originalBytes,
      SensitivePartsSanitizer sensitivePartsSanitizer) {
    super(originalBytes, sensitivePartsSanitizer);
  }

  boolean sanitizeDescriptor() {

    /* Parse descriptor to generate a sanitized version. */
    String masterKeyEd25519FromIdentityEd25519 = null;
    DescriptorBuilder scrubbed = new DescriptorBuilder();
    try (BufferedReader br = new BufferedReader(new StringReader(new String(
        this.originalBytes, StandardCharsets.US_ASCII)))) {
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
            return false;
          }
          hashedBridgeIdentity = DigestUtils.sha1Hex(Hex.decodeHex(
              parts[2].toCharArray())).toLowerCase();
          scrubbed.append("extra-info ").append(parts[1])
              .space().append(hashedBridgeIdentity.toUpperCase()).newLine();

          /* Parse the publication time to determine the file name. */
        } else if (line.startsWith("published ")) {
          scrubbed.append(line).newLine();
          this.publishedString = line.substring("published ".length());

          /* Remove everything from transport lines except the transport
           * name. */
        } else if (line.startsWith("transport ")) {
          if (parts.length < 3) {
            logger.debug("Illegal line in extra-info descriptor: '{}'.  "
                + "Skipping descriptor.", line);
            return false;
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
            return false;
          }

          /* Verify that identity-ed25519 and master-key-ed25519 match. */
        } else if (line.startsWith("master-key-ed25519 ")) {
          masterKeyEd25519 = line.substring(line.indexOf(" ") + 1);
          if (masterKeyEd25519FromIdentityEd25519 != null
              && !masterKeyEd25519FromIdentityEd25519.equals(
              masterKeyEd25519)) {
            logger.warn("Mismatch between identity-ed25519 and "
                + "master-key-ed25519.  Skipping.");
            return false;
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
          return false;
        }
      }
    } catch (DecoderException | IOException e) {
      logger.warn("Could not parse extra-info descriptor.", e);
      return false;
    }

    /* Determine digest(s) of sanitized extra-info descriptor. */
    this.descriptorDigest = this.computeDescriptorDigest(this.originalBytes,
        "extra-info ", "\nrouter-signature\n");
    String descriptorDigestSha256Base64 = null;
    if (masterKeyEd25519FromIdentityEd25519 != null) {
      descriptorDigestSha256Base64 = this.computeSha256Base64Digest(
          this.originalBytes, "extra-info ", "\n-----END SIGNATURE-----\n");
    }
    if (null != descriptorDigestSha256Base64) {
      scrubbed.append("router-digest-sha256 ")
          .append(descriptorDigestSha256Base64).newLine();
    }
    if (null != this.descriptorDigest) {
      scrubbed.append("router-digest ")
          .append(this.descriptorDigest.toUpperCase()).newLine();
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

  public String getDescriptorDigest() {
    return this.descriptorDigest;
  }
}

