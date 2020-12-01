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
import java.util.HashMap;
import java.util.Map;

public class SanitizedBridgeServerDescriptor
    extends SanitizedBridgeDescriptor {

  private static final Logger logger = LoggerFactory.getLogger(
      SanitizedBridgeServerDescriptor.class);

  private String descriptorDigest;

  SanitizedBridgeServerDescriptor(byte[] originalBytes,
      SensitivePartsSanitizer sensitivePartsSanitizer) {
    super(originalBytes, sensitivePartsSanitizer);
  }

  boolean sanitizeDescriptor() {

    if (this.sensitivePartsSanitizer.hasPersistenceProblemWithSecrets()) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return false;
    }

    /* Parse descriptor to generate a sanitized version. */
    String address = null;
    byte[] fingerprintBytes = null;
    StringBuilder scrubbedAddress = null;
    Map<StringBuilder, String> scrubbedTcpPorts = new HashMap<>();
    Map<StringBuilder, String> scrubbedIpAddressesAndTcpPorts = new HashMap<>();
    String masterKeyEd25519FromIdentityEd25519 = null;
    DescriptorBuilder scrubbed = new DescriptorBuilder();
    try (BufferedReader br = new BufferedReader(new StringReader(
        new String(this.originalBytes, StandardCharsets.US_ASCII)))) {
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
            return false;
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
          this.publishedString = line.substring("published ".length());
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
            return false;
          }
          scrubbed.append("extra-info-digest ").append(DigestUtils.sha1Hex(
              Hex.decodeHex(parts[1].toCharArray())).toUpperCase());
          if (parts.length > 2) {
            if (!Base64.isBase64(parts[2])) {
              logger.warn("Illegal base64 character in extra-info-digest line "
                  + "'{}'.  Skipping descriptor.", line);
              return false;
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
          masterKeyEd25519FromIdentityEd25519
              = this.parseMasterKeyEd25519FromIdentityEd25519(sb.toString());
          if (masterKeyEd25519FromIdentityEd25519 == null) {
            logger.warn("Could not parse master-key-ed25519 from "
                + "identity-ed25519.  Skipping descriptor.");
            return false;
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
          return false;
        }
      }
    } catch (Exception e) {
      logger.warn("Could not parse server descriptor.", e);
      return false;
    }

    /* Sanitize the parts that we couldn't sanitize earlier. */
    if (null == address || null == fingerprintBytes
        || null == this.publishedString) {
      logger.warn("Missing either of the following lines that are "
          + "required to sanitize this server bridge descriptor: "
          + "\"router\", \"fingerprint\", \"published\". Skipping "
          + "descriptor.");
      return false;
    }
    try {
      String scrubbedAddressString = this.sensitivePartsSanitizer
          .scrubIpv4Address(address, fingerprintBytes,
          this.getPublishedString());
      if (null == scrubbedAddressString) {
        logger.warn("Invalid IP address in \"router\" line in bridge server "
            + "descriptor. Skipping descriptor.");
        return false;
      }
      scrubbedAddress.append(scrubbedAddressString);
      for (Map.Entry<StringBuilder, String> e
          : scrubbedIpAddressesAndTcpPorts.entrySet()) {
        String scrubbedOrAddress = this.sensitivePartsSanitizer
            .scrubOrAddress(e.getValue(), fingerprintBytes,
            this.getPublishedString());
        if (null == scrubbedOrAddress) {
          logger.warn("Invalid IP address or TCP port in \"or-address\" line "
              + "in bridge server descriptor. Skipping descriptor.");
          return false;
        }
        e.getKey().append(scrubbedOrAddress);
      }
      for (Map.Entry<StringBuilder, String> e : scrubbedTcpPorts.entrySet()) {
        String scrubbedTcpPort = this.sensitivePartsSanitizer
            .scrubTcpPort(e.getValue(), fingerprintBytes,
            this.getPublishedString());
        if (null == scrubbedTcpPort) {
          logger.warn("Invalid TCP port in \"router\" line in bridge server "
              + "descriptor. Skipping descriptor.");
          return false;
        }
        e.getKey().append(scrubbedTcpPort);
      }
    } catch (IOException exception) {
      /* There's a persistence problem, so we shouldn't scrub more IP addresses
       * or TCP ports in this execution. */
      return false;
    }

    /* Determine digest(s) of sanitized server descriptor. */
    this.descriptorDigest = this.computeDescriptorDigest(this.originalBytes,
        "router ", "\nrouter-signature\n");
    String descriptorDigestSha256Base64 = null;
    if (masterKeyEd25519FromIdentityEd25519 != null) {
      descriptorDigestSha256Base64 = this.computeSha256Base64Digest(
          this.originalBytes, "router ", "\n-----END SIGNATURE-----\n");
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

