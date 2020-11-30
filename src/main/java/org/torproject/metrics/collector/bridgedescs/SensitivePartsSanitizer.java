/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import static java.time.ZoneOffset.UTC;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class SensitivePartsSanitizer {

  private static final Logger logger = LoggerFactory.getLogger(
      SensitivePartsSanitizer.class);

  private boolean replaceIpAddressesWithHashes = false;

  private Path bridgeIpSecretsFile;

  private boolean persistenceProblemWithSecrets;

  private final SortedMap<String, byte[]> secretsForHashingIpAddresses
      = new TreeMap<>();

  private String bridgeSanitizingCutOffTimestamp;

  private SecureRandom secureRandom;

  private boolean haveWarnedAboutInterval;

  SensitivePartsSanitizer() {
    /* Nothing to do, if we're not using secrets for computing hashes. */
  }

  SensitivePartsSanitizer(Path bridgeIpSecretsFile,
      long limitBridgeSanitizingIntervalDays) {
    this.bridgeIpSecretsFile = bridgeIpSecretsFile;
    this.readBridgeIpSecretsFile();
    this.determineCutOffTimestamp(limitBridgeSanitizingIntervalDays);
    this.replaceIpAddressesWithHashes = true;
    this.initializeSecureRandom();
  }

  /* Read hex-encoded secrets for replacing IP addresses with hashes
   * from disk. */
  private void readBridgeIpSecretsFile() {
    if (Files.exists(this.bridgeIpSecretsFile)) {
      try {
        for (String line : Files.readAllLines(bridgeIpSecretsFile)) {
          String[] parts = line.split(",");
          if ((line.length() != ("yyyy-MM,".length() + 31 * 2)
              && line.length() != ("yyyy-MM,".length() + 50 * 2)
              && line.length() != ("yyyy-MM,".length() + 83 * 2))
              || parts.length != 2) {
            logger.warn("Invalid line in bridge-ip-secrets file "
                + "starting with '{}'! "
                + "Not calculating any IP address hashes in this "
                + "execution!", line.substring(0, 7));
            this.persistenceProblemWithSecrets = true;
            break;
          }
          String month = parts[0];
          byte[] secret = Hex.decodeHex(parts[1].toCharArray());
          this.secretsForHashingIpAddresses.put(month, secret);
        }
        if (!this.persistenceProblemWithSecrets) {
          logger.debug("Read {} secrets for hashing bridge IP addresses.",
              this.secretsForHashingIpAddresses.size());
        }
      } catch (DecoderException e) {
        logger.warn("Failed to decode hex string in {}! Not calculating any IP "
            + "address hashes in this execution!", bridgeIpSecretsFile, e);
        this.persistenceProblemWithSecrets = true;
      } catch (IOException e) {
        logger.warn("Failed to read {}! Not calculating any IP "
            + "address hashes in this execution!", bridgeIpSecretsFile, e);
        this.persistenceProblemWithSecrets = true;
      }
    }
  }

  boolean hasPersistenceProblemWithSecrets() {
    return this.persistenceProblemWithSecrets;
  }

  private void determineCutOffTimestamp(
      long limitBridgeSanitizingIntervalDays) {

    /* If we're configured to keep secrets only for a limited time, define
     * the cut-off day and time. */
    LocalDateTime bridgeSanitizingCutOffDateTime
        = LocalDateTime.of(1999, 12, 31, 23, 59, 59);
    if (limitBridgeSanitizingIntervalDays >= 0L) {
      LocalDateTime configuredBridgeSanitizingCutOffDateTime
          = LocalDateTime.now(UTC).minusDays(limitBridgeSanitizingIntervalDays);
      if (configuredBridgeSanitizingCutOffDateTime.isAfter(
          bridgeSanitizingCutOffDateTime)) {
        bridgeSanitizingCutOffDateTime
            = configuredBridgeSanitizingCutOffDateTime;
      }
    }
    this.bridgeSanitizingCutOffTimestamp = bridgeSanitizingCutOffDateTime
        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

    logger.info("Using cut-off datetime '{}' for secrets.",
        this.bridgeSanitizingCutOffTimestamp);
  }

  private void initializeSecureRandom() {
    /* Initialize secure random number generator. */
    try {
      this.secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
    } catch (GeneralSecurityException e) {
      logger.warn("Could not initialize secure "
          + "random number generator! Not calculating any IP address "
          + "hashes in this execution!", e);
      this.persistenceProblemWithSecrets = true;
    }
  }

  String scrubOrAddress(String orAddress, byte[] fingerprintBytes,
      String published) throws IOException {
    if (!orAddress.contains(":")) {
      /* Malformed or-address or a line. */
      return null;
    }
    String addressPart = orAddress.substring(0,
        orAddress.lastIndexOf(":"));
    String portPart = orAddress.substring(orAddress.lastIndexOf(":") + 1);
    String scrubbedAddressPart;
    if (addressPart.startsWith("[")) {
      scrubbedAddressPart = this.scrubIpv6Address(addressPart,
          fingerprintBytes, published);
    } else {
      scrubbedAddressPart = this.scrubIpv4Address(addressPart,
          fingerprintBytes, published);
    }
    String scrubbedPort = this.scrubTcpPort(portPart, fingerprintBytes,
        published);
    return (scrubbedAddressPart == null ? null :
        scrubbedAddressPart + ":" + scrubbedPort);
  }

  String scrubIpv4Address(String address, byte[] fingerprintBytes,
      String published) throws IOException {
    if (this.replaceIpAddressesWithHashes) {
      if (this.persistenceProblemWithSecrets) {
        /* There's a persistence problem, so we shouldn't scrub more IP
         * addresses in this execution. */
        return null;
      }
      byte[] hashInput = new byte[4 + 20 + 31];
      String[] ipParts = address.split("\\.");
      for (int i = 0; i < 4; i++) {
        hashInput[i] = (byte) Integer.parseInt(ipParts[i]);
      }
      System.arraycopy(fingerprintBytes, 0, hashInput, 4, 20);
      byte[] secret = this.getSecretForMonth(published);
      System.arraycopy(secret, 0, hashInput, 24, 31);
      byte[] hashOutput = DigestUtils.sha256(hashInput);
      return "10."
          + (((int) hashOutput[0] + 256) % 256) + "."
          + (((int) hashOutput[1] + 256) % 256) + "."
          + (((int) hashOutput[2] + 256) % 256);
    } else {
      return "127.0.0.1";
    }
  }

  private String scrubIpv6Address(String address, byte[] fingerprintBytes,
      String published) throws IOException {
    StringBuilder sb = new StringBuilder("[fd9f:2e19:3bcf::");
    if (this.replaceIpAddressesWithHashes) {
      if (this.persistenceProblemWithSecrets) {
        /* There's a persistence problem, so we shouldn't scrub more IP
         * addresses in this execution. */
        return null;
      }
      String[] doubleColonSeparatedParts = address.substring(1,
          address.length() - 1).split("::", -1);
      if (doubleColonSeparatedParts.length > 2) {
        /* Invalid IPv6 address. */
        return null;
      }
      List<String> hexParts = new ArrayList<>();
      for (String doubleColonSeparatedPart : doubleColonSeparatedParts) {
        StringBuilder hexPart = new StringBuilder();
        String[] parts = doubleColonSeparatedPart.split(":", -1);
        if (parts.length < 1 || parts.length > 8) {
          /* Invalid IPv6 address. */
          return null;
        }
        for (String part : parts) {
          if (part.contains(".")) {
            String[] ipParts = part.split("\\.");
            byte[] ipv4Bytes = new byte[4];
            if (ipParts.length != 4) {
              /* Invalid IPv4 part in IPv6 address. */
              return null;
            }
            for (int m = 0; m < 4; m++) {
              ipv4Bytes[m] = (byte) Integer.parseInt(ipParts[m]);
            }
            hexPart.append(Hex.encodeHexString(ipv4Bytes));
          } else if (part.length() > 4) {
            /* Invalid IPv6 address. */
            return null;
          } else {
            for (int k = part.length(); k < 4; k++) {
              hexPart.append("0");
            }
            hexPart.append(part);
          }
        }
        hexParts.add(hexPart.toString());
      }
      StringBuilder hex = new StringBuilder();
      hex.append(hexParts.get(0));
      if (hexParts.size() == 2) {
        for (int i = 32 - hexParts.get(0).length()
            - hexParts.get(1).length(); i > 0; i--) {
          hex.append("0");
        }
        hex.append(hexParts.get(1));
      }
      byte[] ipBytes;
      try {
        ipBytes = Hex.decodeHex(hex.toString().toCharArray());
      } catch (DecoderException e) {
        /* TODO Invalid IPv6 address. */
        return null;
      }
      if (ipBytes.length != 16) {
        /* TODO Invalid IPv6 address. */
        return null;
      }
      byte[] hashInput = new byte[16 + 20 + 19];
      System.arraycopy(ipBytes, 0, hashInput, 0, 16);
      System.arraycopy(fingerprintBytes, 0, hashInput, 16, 20);
      byte[] secret = this.getSecretForMonth(published);
      System.arraycopy(secret, 31, hashInput, 36, 19);
      String hashOutput = DigestUtils.sha256Hex(hashInput);
      sb.append(hashOutput, hashOutput.length() - 6, hashOutput.length() - 4);
      sb.append(":");
      sb.append(hashOutput.substring(hashOutput.length() - 4));
    }
    sb.append("]");
    return sb.toString();
  }

  String scrubTcpPort(String portString, byte[] fingerprintBytes,
      String published) throws IOException {
    if (portString.equals("0")) {
      return "0";
    } else if (this.replaceIpAddressesWithHashes) {
      if (this.persistenceProblemWithSecrets) {
        /* There's a persistence problem, so we shouldn't scrub more TCP
         * ports in this execution. */
        return null;
      }
      byte[] hashInput = new byte[2 + 20 + 33];
      int portNumber = Integer.parseInt(portString);
      hashInput[0] = (byte) (portNumber >> 8);
      hashInput[1] = (byte) portNumber;
      System.arraycopy(fingerprintBytes, 0, hashInput, 2, 20);
      byte[] secret = this.getSecretForMonth(published);
      System.arraycopy(secret, 50, hashInput, 22, 33);
      byte[] hashOutput = DigestUtils.sha256(hashInput);
      int hashedPort = ((((hashOutput[0] & 0b1111_1111) << 8)
          | (hashOutput[1] & 0b1111_1111)) >> 2) | 0b1100_0000_0000_0000;
      return String.valueOf(hashedPort);
    } else {
      return "1";
    }
  }

  private byte[] getSecretForMonth(String published) throws IOException {
    if (this.bridgeSanitizingCutOffTimestamp
        .compareTo(published) > 0) {
      String text = "Sanitizing and storing bridge descriptor with publication "
          + "time outside our descriptor sanitizing interval.";
      if (this.haveWarnedAboutInterval) {
        logger.debug(text);
      } else {
        logger.warn(text);
        this.haveWarnedAboutInterval = true;
      }
    }
    String month = published.substring(0, "yyyy-MM".length());
    if (!this.secretsForHashingIpAddresses.containsKey(month)
        || this.secretsForHashingIpAddresses.get(month).length < 83) {
      byte[] secret = new byte[83];
      this.secureRandom.nextBytes(secret);
      if (this.secretsForHashingIpAddresses.containsKey(month)) {
        System.arraycopy(this.secretsForHashingIpAddresses.get(month), 0,
            secret, 0,
            this.secretsForHashingIpAddresses.get(month).length);
      }
      if (month.compareTo(
          this.bridgeSanitizingCutOffTimestamp) < 0) {
        logger.warn("Generated a secret that we won't make "
            + "persistent, because it's outside our bridge descriptor "
            + "sanitizing interval.");
      } else {
        /* Append secret to file on disk immediately before using it, or
         * we might end with inconsistently sanitized bridges. */
        byte[] newBytes = (month + "," + Hex.encodeHexString(secret) + "\n")
            .getBytes();
        try {
          if (Files.exists(this.bridgeIpSecretsFile)) {
            Files.write(this.bridgeIpSecretsFile, newBytes,
                StandardOpenOption.APPEND);
          } else {
            Files.createDirectories(this.bridgeIpSecretsFile.getParent());
            Files.write(this.bridgeIpSecretsFile, newBytes);
          }
        } catch (IOException e) {
          logger.warn("Could not store new secret "
              + "to disk! Not calculating any IP address or TCP port "
              + "hashes in this execution!", e);
          this.persistenceProblemWithSecrets = true;
          throw new IOException(e);
        }
      }
      this.secretsForHashingIpAddresses.put(month, secret);
    }
    return this.secretsForHashingIpAddresses.get(month);
  }

  void finishWriting() {

    /* Delete secrets that we don't need anymore. */
    if (!this.secretsForHashingIpAddresses.isEmpty()
        && this.secretsForHashingIpAddresses.firstKey().compareTo(
        this.bridgeSanitizingCutOffTimestamp) < 0) {
      try {
        int kept = 0;
        int deleted = 0;
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, byte[]> e :
            this.secretsForHashingIpAddresses.entrySet()) {
          if (e.getKey().compareTo(
              this.bridgeSanitizingCutOffTimestamp) < 0) {
            deleted++;
          } else {
            lines.add(e.getKey() + "," + Hex.encodeHexString(e.getValue()));
            kept++;
          }
        }
        Files.write(bridgeIpSecretsFile, lines);
        logger.info("Deleted {} secrets that we don't "
            + "need anymore and kept {}.", deleted, kept);
      } catch (IOException e) {
        logger.warn("Could not store reduced set of "
            + "secrets to disk! This is a bad sign, better check what's "
            + "going on!", e);
      }
    }
  }
}

