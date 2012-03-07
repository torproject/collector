/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.security.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.*;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.digest.*;
import org.apache.commons.codec.binary.*;

/**
 * Sanitizes bridge descriptors, i.e., removes all possibly sensitive
 * information from them, and writes them to a local directory structure.
 * During the sanitizing process, all information about the bridge
 * identity or IP address are removed or replaced. The goal is to keep the
 * sanitized bridge descriptors useful for statistical analysis while not
 * making it easier for an adversary to enumerate bridges.
 *
 * There are three types of bridge descriptors: bridge network statuses
 * (lists of all bridges at a given time), server descriptors (published
 * by the bridge to advertise their capabilities), and extra-info
 * descriptors (published by the bridge, mainly for statistical analysis).
 *
 * Network statuses, server descriptors, and extra-info descriptors are
 * linked via descriptor digests: extra-info descriptors are referenced
 * from server descriptors, and server descriptors are referenced from
 * network statuses. These references need to be changed during the
 * sanitizing process, because descriptor contents change and so do the
 * descriptor digests.
 *
 * No assumptions are made about the order in which bridge descriptors are
 * parsed. The approach taken here is to sanitize bridge descriptors even
 * with incomplete knowledge about references and to update them as soon
 * as these information get known. We are keeping a persistent data
 * structure, the bridge descriptor mapping, to hold information about
 * every single descriptor. The idea is that every descriptor is (a)
 * referenced from a network status and consists of (b) a server
 * descriptor and (c) an extra-info descriptor, both of which are
 * published at the same time. Using this data structure, we can repair
 * references as soon as we learn more about the descriptor and regardless
 * of the order of incoming bridge descriptors.
 *
 * The process of sanitizing a bridge descriptor is as follows, depending
 * on the type of descriptor:
 *
 * Network statuses are processed by sanitizing every r line separately
 * and looking up whether the descriptor mapping contains a bridge with
 * given identity hash and descriptor publication time. If so, the new
 * server descriptor identifier can be added. If not, we're adding all
 * 0's.
 *
 * While sanitizing a server descriptor, its identity hash and publication
 * time are looked up in order to put in the extra-info descriptor
 * identifier in case the corresponding extra-info descriptor was
 * sanitized before. Further, its publication time is noted down, so that
 * all network statuses that might be referencing this server descriptor
 * can be re-written at the end of the sanitizing procedure.
 *
 * Extra-info descriptors are processed by looking up their identity hash
 * and publication time in the descriptor mapping. If the corresponding
 * server descriptor was sanitized before, the server descriptor is
 * re-written to include the new extra-info descriptor digest, and the
 * publication time is noted down in order to re-write the network
 * statuses possibly referencing this extra-info descriptor and its
 * corresponding server descriptor at the end of the sanitizing process.
 *
 * After sanitizing all bridge descriptors, the network statuses that
 * might be referencing server descriptors which have been (re-)written
 * during this execution are re-written, too. This may be necessary in
 * order to update previously broken references to server descriptors.
 */
public class SanitizedBridgesWriter {

  /**
   * Hex representation of null reference that is written to bridge
   * descriptors if we don't have the real reference, yet.
   */
  private static final String NULL_REFERENCE =
      "0000000000000000000000000000000000000000";

  /**
   * Mapping between a descriptor as referenced from a network status to
   * the digests of server descriptor and extra-info descriptor.
   */
  private static class DescriptorMapping {

    /**
     * Creates a new mapping from comma-separated values as read from the
     * persistent mapping file.
     */
    private DescriptorMapping(String commaSeparatedValues) {
      String[] parts = commaSeparatedValues.split(",");
      this.hashedBridgeIdentity = parts[0];
      this.published = parts[1];
      this.serverDescriptorIdentifier = parts[2];
      this.extraInfoDescriptorIdentifier = parts[3];
    }

    /**
     * Creates a new mapping for a given identity hash and descriptor
     * publication time that has all 0's as descriptor digests.
     */
    private DescriptorMapping(String hashedBridgeIdentity,
        String published) {
      this.hashedBridgeIdentity = hashedBridgeIdentity;
      this.published = published;
      this.serverDescriptorIdentifier = NULL_REFERENCE;
      this.extraInfoDescriptorIdentifier = NULL_REFERENCE;
    }
    private String hashedBridgeIdentity;
    private String published;
    private String serverDescriptorIdentifier;
    private String extraInfoDescriptorIdentifier;

    /**
     * Returns a string representation of this descriptor mapping that can
     * be written to the persistent mapping file.
     */
    public String toString() {
      return this.hashedBridgeIdentity + "," + this.published + ","
      + this.serverDescriptorIdentifier + ","
      + this.extraInfoDescriptorIdentifier;
    }
  }

  /**
   * File containing the mapping between network status entries, server
   * descriptors, and extra-info descriptors.
   */
  private File bridgeDescriptorMappingsFile;

  /**
   * Mapping between status entries, server descriptors, and extra-info
   * descriptors. This mapping is required to re-establish the references
   * from status entries to server descriptors and from server descriptors
   * to extra-info descriptors. The original references are broken when
   * sanitizing, because descriptor contents change and so do the
   * descriptor digests that are used for referencing. Map key contains
   * hashed bridge identity and descriptor publication time, map value
   * contains map key plus new server descriptor identifier and new
   * extra-info descriptor identifier.
   */
  private SortedMap<String, DescriptorMapping> bridgeDescriptorMappings;

  /**
   * Logger for this class.
   */
  private Logger logger;

  /**
   * Publication times of server descriptors and extra-info descriptors
   * parsed in the current execution. These times are used to determine
   * which statuses need to be rewritten at the end of the execution.
   */
  private SortedSet<String> descriptorPublicationTimes;

  /**
   * Output directory for writing sanitized bridge descriptors.
   */
  private File sanitizedBridgesDirectory;

  private File statsDirectory;

  private boolean replaceIPAddressesWithHashes;

  private boolean persistenceProblemWithSecrets;

  private SortedMap<String, byte[]> secretsForHashingIPAddresses;

  private String bridgeDescriptorMappingsCutOffTimestamp;

  private boolean haveWarnedAboutLimitedMapping;

  private File bridgeIpSecretsFile;

  private SecureRandom secureRandom;

  /**
   * Initializes this class, including reading in the known descriptor
   * mapping.
   */
  public SanitizedBridgesWriter(File sanitizedBridgesDirectory,
      File statsDirectory, boolean replaceIPAddressesWithHashes,
      long limitBridgeDescriptorMappings) {

    if (sanitizedBridgesDirectory == null || statsDirectory == null) {
      throw new IllegalArgumentException();
    }

    /* Memorize argument values. */
    this.sanitizedBridgesDirectory = sanitizedBridgesDirectory;
    this.statsDirectory = statsDirectory;
    this.replaceIPAddressesWithHashes = replaceIPAddressesWithHashes;

    /* Initialize logger. */
    this.logger = Logger.getLogger(
        SanitizedBridgesWriter.class.getName());

    /* Initialize data structure. */
    this.bridgeDescriptorMappings = new TreeMap<String,
        DescriptorMapping>();
    this.descriptorPublicationTimes = new TreeSet<String>();

    /* Initialize secure random number generator if we need it. */
    if (this.replaceIPAddressesWithHashes) {
      try {
        this.secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
      } catch (GeneralSecurityException e) {
        this.logger.log(Level.WARNING, "Could not initialize secure "
            + "random number generator! Not calculating any IP address "
            + "hashes in this execution!", e);
        this.persistenceProblemWithSecrets = true;
      }
    }

    /* Read hex-encoded secrets for replacing IP addresses with hashes
     * from disk. */
    this.secretsForHashingIPAddresses = new TreeMap<String, byte[]>();
    this.bridgeIpSecretsFile = new File(statsDirectory,
        "bridge-ip-secrets");
    if (this.bridgeIpSecretsFile.exists()) {
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            this.bridgeIpSecretsFile));
        String line;
        while ((line = br.readLine()) != null) {
          String[] parts = line.split(",");
          if ((line.length() != ("yyyy-MM,".length() + 31 * 2) &&
              line.length() != ("yyyy-MM,".length() + 50 * 2)) ||
              parts.length != 2) {
            this.logger.warning("Invalid line in bridge-ip-secrets file "
                + "starting with '" + line.substring(0, 7) + "'! "
                + "Not calculating any IP address hashes in this "
                + "execution!");
            this.persistenceProblemWithSecrets = true;
            break;
          }
          String month = parts[0];
          byte[] secret = Hex.decodeHex(parts[1].toCharArray());
          this.secretsForHashingIPAddresses.put(month, secret);
        }
        if (!this.persistenceProblemWithSecrets) {
          this.logger.fine("Read "
              + this.secretsForHashingIPAddresses.size() + " secrets for "
              + "hashing bridge IP addresses.");
        }
      } catch (DecoderException e) {
        this.logger.log(Level.WARNING, "Failed to decode hex string in "
            + this.bridgeIpSecretsFile + "! Not calculating any IP "
            + "address hashes in this execution!", e);
        this.persistenceProblemWithSecrets = true;
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Failed to read "
            + this.bridgeIpSecretsFile + "! Not calculating any IP "
            + "address hashes in this execution!", e);
        this.persistenceProblemWithSecrets = true;
      }
    }

    /* If we're configured to keep descriptor mappings only for a limited
     * time, define the cut-off day and time. */
    if (limitBridgeDescriptorMappings >= 0L) {
      SimpleDateFormat formatter = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
      this.bridgeDescriptorMappingsCutOffTimestamp = formatter.format(
          System.currentTimeMillis() - 24L * 60L * 60L * 1000L
          * limitBridgeDescriptorMappings);
    } else {
      this.bridgeDescriptorMappingsCutOffTimestamp =
          "1999-12-31 23:59:59";
    }

    /* Read known descriptor mappings from disk. */
    this.bridgeDescriptorMappingsFile = new File(
        "stats/bridge-descriptor-mappings");
    if (this.bridgeDescriptorMappingsFile.exists()) {
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            this.bridgeDescriptorMappingsFile));
        String line = null;
        int read = 0, skipped = 0;
        while ((line = br.readLine()) != null) {
          if (line.split(",").length == 4) {
            String[] parts = line.split(",");
            if (this.bridgeDescriptorMappingsCutOffTimestamp.
                compareTo(parts[1]) > 0) {
              skipped++;
              continue;
            }
            read++;
            DescriptorMapping dm = new DescriptorMapping(line);
            this.bridgeDescriptorMappings.put(parts[0] + "," + parts[1],
                dm);
          } else {
            this.logger.warning("Corrupt line '" + line + "' in "
                + this.bridgeDescriptorMappingsFile.getAbsolutePath()
                + ". Skipping.");
            continue;
          }
        }
        br.close();
        this.logger.fine("Finished reading " + read + " descriptor "
            + "mappings from disk, skipped " + skipped + ".");
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Could not read in "
            + this.bridgeDescriptorMappingsFile.getAbsolutePath()
            + ".");
        return;
      }
    }
  }

  private String scrubOrAddress(String orAddress, byte[] fingerprintBytes,
      String published) throws IOException {
    if (!orAddress.contains(":")) {
      /* Malformed or-address or a line. */
      return null;
    }
    String addressPart = orAddress.substring(0,
        orAddress.lastIndexOf(":"));
    String portPart = orAddress.substring(orAddress.lastIndexOf(":") + 1);
    String scrubbedAddressPart = null;
    if (addressPart.startsWith("[")) {
      scrubbedAddressPart = this.scrubIpv6Address(addressPart,
          fingerprintBytes, published);
    } else {
      scrubbedAddressPart = this.scrubIpv4Address(addressPart,
          fingerprintBytes, published);
    }
    return (scrubbedAddressPart == null ? null :
          scrubbedAddressPart + ":" + portPart);
  }

  private String scrubIpv4Address(String address, byte[] fingerprintBytes,
      String published) throws IOException {
    if (this.replaceIPAddressesWithHashes) {
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
      String month = published.substring(0, "yyyy-MM".length());
      byte[] secret = this.getSecretForMonth(month);
      System.arraycopy(secret, 0, hashInput, 24, 31);
      byte[] hashOutput = DigestUtils.sha256(hashInput);
      String hashedAddress = "10."
          + (((int) hashOutput[0] + 256) % 256) + "."
          + (((int) hashOutput[1] + 256) % 256) + "."
          + (((int) hashOutput[2] + 256) % 256);
      return hashedAddress;
    } else {
      return "127.0.0.1";
    }
  }

  private String scrubIpv6Address(String address, byte[] fingerprintBytes,
      String published) throws IOException {
    StringBuilder sb = new StringBuilder("[fd9f:2e19:3bcf::");
    if (this.replaceIPAddressesWithHashes) {
      if (this.persistenceProblemWithSecrets) {
        /* There's a persistence problem, so we shouldn't scrub more IP
         * addresses in this execution. */
        return null;
      }
      byte[] hashInput = new byte[16 + 20 + 19];
      StringBuilder hex = new StringBuilder();
      String[] parts = address.substring(1, address.length() - 1).
          split(":", -1);
      if (parts.length < 1 || parts.length > 8) {
        /* Invalid IPv6 address. */
        return null;
      }
      for (int i = 0; i < parts.length; i++) {
        String part = parts[i];
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
          hex.append(Hex.encodeHexString(ipv4Bytes));
        } else if (part.length() > 4) {
          /* Invalid IPv6 address. */
          return null;
        } else if (part.length() < 1) {
          int j = parts.length - 1;
          if (address.contains(".")) {
            j++;
          }
          for (; j < 8; j++) {
            hex.append("0000");
          }
        } else {
          for (int k = part.length(); k < 4; k++) {
            hex.append("0");
          }
          hex.append(part);
        }
      }
      byte[] ipBytes = null;
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
      System.arraycopy(ipBytes, 0, hashInput, 0, 16);
      System.arraycopy(fingerprintBytes, 0, hashInput, 16, 20);
      String month = published.substring(0, "yyyy-MM".length());
      byte[] secret = this.getSecretForMonth(month);
      System.arraycopy(secret, 31, hashInput, 36, 19);
      String hashOutput = DigestUtils.sha256Hex(hashInput);
      sb.append(hashOutput.substring(hashOutput.length() - 6,
          hashOutput.length() - 4));
      sb.append(":");
      sb.append(hashOutput.substring(hashOutput.length() - 4));
    }
    sb.append("]");
    return sb.toString();
  }

  private byte[] getSecretForMonth(String month) throws IOException {
    if (!this.secretsForHashingIPAddresses.containsKey(month) ||
        this.secretsForHashingIPAddresses.get(month).length == 31) {
      byte[] secret = new byte[50];
      this.secureRandom.nextBytes(secret);
      if (this.secretsForHashingIPAddresses.containsKey(month)) {
        System.arraycopy(this.secretsForHashingIPAddresses.get(month), 0,
            secret, 0, 31);
      }
      if (month.compareTo(
          this.bridgeDescriptorMappingsCutOffTimestamp) < 0) {
        this.logger.warning("Generated a secret that we won't make "
            + "persistent, because it's outside our bridge descriptors "
            + "mapping interval.");
      } else {
        /* Append secret to file on disk immediately before using it, or
         * we might end with inconsistently sanitized bridges. */
        try {
          if (!this.bridgeIpSecretsFile.exists()) {
            this.bridgeIpSecretsFile.getParentFile().mkdirs();
          }
          BufferedWriter bw = new BufferedWriter(new FileWriter(
              this.bridgeIpSecretsFile,
              this.bridgeIpSecretsFile.exists()));
          bw.write(month + "," + Hex.encodeHexString(secret) + "\n");
          bw.close();
        } catch (IOException e) {
          this.logger.log(Level.WARNING, "Could not store new secret "
              + "to disk! Not calculating any IP address hashes in "
              + "this execution!", e);
          this.persistenceProblemWithSecrets = true;
          throw new IOException(e);
        }
      }
      this.secretsForHashingIPAddresses.put(month, secret);
    }
    return this.secretsForHashingIPAddresses.get(month);
  }

  /**
   * Sanitizes a network status and writes it to disk. Processes every r
   * line separately and looks up whether the descriptor mapping contains
   * a bridge with given identity hash and descriptor publication time. */
  public void sanitizeAndStoreNetworkStatus(byte[] data,
      String publicationTime) {

    if (this.persistenceProblemWithSecrets) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return;
    }

    if (this.bridgeDescriptorMappingsCutOffTimestamp.
        compareTo(publicationTime) > 0) {
      this.logger.log(!this.haveWarnedAboutLimitedMapping ? Level.WARNING
          : Level.FINE, "Sanitizing and storing network status with "
          + "publication time outside our descriptor mapping interval. "
          + "We might not be able to repair references.");
      this.haveWarnedAboutLimitedMapping = true;
    }

    /* Parse the given network status line by line. */
    SortedMap<String, String> scrubbedLines =
        new TreeMap<String, String>();
    try {
      StringBuilder scrubbed = new StringBuilder();
      BufferedReader br = new BufferedReader(new StringReader(new String(
          data, "US-ASCII")));
      String line = null;
      String mostRecentDescPublished = null;
      byte[] fingerprintBytes = null;
      String descPublicationTime = null;
      while ((line = br.readLine()) != null) {

        /* r lines contain sensitive information that needs to be removed
         * or replaced. */
        if (line.startsWith("r ")) {

          /* Parse the relevant parts of this r line. */
          String[] parts = line.split(" ");
          fingerprintBytes = Base64.decodeBase64(parts[2] + "==");
          descPublicationTime = parts[4] + " " + parts[5];
          String address = parts[6];
          String orPort = parts[7];
          String dirPort = parts[8];

          /* Look up the descriptor in the descriptor mapping, or add a
           * new mapping entry if there is none. */
          String hashedBridgeIdentityHex = Hex.encodeHexString(
              DigestUtils.sha(fingerprintBytes)).toLowerCase();
          String mappingKey = hashedBridgeIdentityHex + ","
              + descPublicationTime;
          DescriptorMapping mapping = null;
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentityHex.
                toLowerCase(), descPublicationTime);
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }

          /* Determine most recent descriptor publication time. */
          if (descPublicationTime.compareTo(publicationTime) <= 0 &&
              (mostRecentDescPublished == null ||
              descPublicationTime.compareTo(mostRecentDescPublished) > 0)) {
            mostRecentDescPublished = descPublicationTime;
          }

          /* Write scrubbed r line to buffer. */
          String hashedBridgeIdentityBase64 = Base64.encodeBase64String(
              DigestUtils.sha(fingerprintBytes)).substring(0, 27);
          String sdi = Base64.encodeBase64String(Hex.decodeHex(
                mapping.serverDescriptorIdentifier.toCharArray())).
                substring(0, 27);
          String scrubbedAddress = null;
          try {
            scrubbedAddress = scrubIpv4Address(address, fingerprintBytes,
                descPublicationTime);
          } catch (IOException e) {
            return;
          }
          if (scrubbed.length() > 0) {
            String scrubbedLine = scrubbed.toString();
            scrubbedLines.put(scrubbedLine.split(" ")[2], scrubbedLine);
            scrubbed = new StringBuilder();
          }
          scrubbed.append("r Unnamed "
              + hashedBridgeIdentityBase64 + " " + sdi + " "
              + descPublicationTime + " " + scrubbedAddress + " "
              + orPort + " " + dirPort + "\n");

        /* Sanitize any addresses in a lines using the fingerprint and
         * descriptor publication time from the previous r line. */
        } else if (line.startsWith("a ")) {
          String scrubbedOrAddress = scrubOrAddress(
              line.substring("a ".length()), fingerprintBytes,
              descPublicationTime);
          if (scrubbedOrAddress != null) {
            scrubbed.append("a " + scrubbedOrAddress + "\n");
          } else {
            this.logger.warning("Invalid address in line '" + line
                + "' in bridge network status.  Skipping line!");
          }

        /* Nothing special about s, w, and p lines; just copy them. */
        } else if (line.startsWith("s ") || line.equals("s") ||
            line.startsWith("w ") || line.equals("w") ||
            line.startsWith("p ") || line.equals("p")) {
          scrubbed.append(line + "\n");

        /* There should be nothing else but r, w, p, and s lines in the
         * network status.  If there is, we should probably learn before
         * writing anything to the sanitized descriptors. */
        } else {
          this.logger.fine("Unknown line '" + line + "' in bridge "
              + "network status. Not writing to disk!");
          return;
        }
      }
      br.close();
      if (scrubbed.length() > 0) {
        String scrubbedLine = scrubbed.toString();
        scrubbedLines.put(scrubbedLine.split(" ")[2], scrubbedLine);
        scrubbed = new StringBuilder();
      }

      /* Check if we can tell from the descriptor publication times
       * whether this status is possibly stale. */
      SimpleDateFormat formatter = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
      if (formatter.parse(publicationTime).getTime() -
          formatter.parse(mostRecentDescPublished).getTime() >
          60L * 60L * 1000L) {
        this.logger.warning("The most recent descriptor in the bridge "
            + "network status published at " + publicationTime + " was "
            + "published at " + mostRecentDescPublished + " which is "
            + "more than 1 hour before the status. This is a sign for "
            + "the status being stale. Please check!");
      }
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not parse timestamp in "
          + "bridge network status.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not parse bridge network "
          + "status.", e);
      return;
    } catch (DecoderException e) {
      this.logger.log(Level.WARNING, "Could not parse bridge network "
          + "status.", e);
      return;
    }

    /* Write the sanitized network status to disk. */
    try {

      /* Determine file name. */
      String syear = publicationTime.substring(0, 4);
      String smonth = publicationTime.substring(5, 7);
      String sday = publicationTime.substring(8, 10);
      String stime = publicationTime.substring(11, 13)
          + publicationTime.substring(14, 16)
          + publicationTime.substring(17, 19);
      File statusFile = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/" + syear
          + "/" + smonth + "/statuses/" + sday + "/" + syear + smonth
          + sday + "-" + stime + "-"
          + "4A0CCD2DDC7995083D73F5D667100C8A5831F16D");

      /* Create all parent directories to write this network status. */
      statusFile.getParentFile().mkdirs();

      /* Write sanitized network status to disk. */
      BufferedWriter bw = new BufferedWriter(new FileWriter(statusFile));
      for (String scrubbed : scrubbedLines.values()) {
        bw.write(scrubbed);
      }
      bw.close();

    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write sanitized bridge "
          + "network status to disk.", e);
      return;
    }
  }

  /**
   * Sanitizes a bridge server descriptor and writes it to disk. Looks up
   * up bridge identity hash and publication time in the descriptor
   * mapping. After sanitizing a server descriptor, its publication time
   * is noted down, so that all network statuses that might be referencing
   * this server descriptor can be re-written at the end of the sanitizing
   * procedure.
   */
  public void sanitizeAndStoreServerDescriptor(byte[] data) {

    if (this.persistenceProblemWithSecrets) {
      /* There's a persistence problem, so we shouldn't scrub more IP
       * addresses in this execution. */
      return;
    }

    /* Parse descriptor to generate a sanitized version and to look it up
     * in the descriptor mapping. */
    String scrubbedDesc = null;
    DescriptorMapping mapping = null;
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(data, "US-ASCII")));
      StringBuilder scrubbed = new StringBuilder();
      String line = null, hashedBridgeIdentity = null, address = null,
          published = null, routerLine = null, scrubbedAddress = null;
      List<String> orAddresses = null, scrubbedOrAddresses = null;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {

        /* When we have parsed both published and fingerprint line, look
         * up descriptor in the descriptor mapping or create a new one if
         * there is none. */
        if (mapping == null && published != null &&
            hashedBridgeIdentity != null) {
          String mappingKey = hashedBridgeIdentity + "," + published;
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentity,
                published);
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }
        }

        /* Skip all crypto parts that might be used to derive the bridge's
         * identity fingerprint. */
        if (skipCrypto && !line.startsWith("-----END ")) {
          continue;

        /* Store the router line for later processing, because we may need
         * the bridge identity fingerprint for replacing the IP address in
         * the scrubbed version.  */
        } else if (line.startsWith("router ")) {
          address = line.split(" ")[2];
          routerLine = line;

        /* Store or-address parts in a list and sanitize them when we have
         * read the fingerprint. */
        } else if (line.startsWith("or-address ")) {
          if (orAddresses == null) {
            orAddresses = new ArrayList<String>();
          }
          orAddresses.add(line.substring("or-address ".length()));

        /* Parse the publication time and add it to the list of descriptor
         * publication times to re-write network statuses at the end of
         * the sanitizing procedure. */
        } else if (line.startsWith("published ")) {
          published = line.substring("published ".length());
          if (this.bridgeDescriptorMappingsCutOffTimestamp.
              compareTo(published) > 0) {
            this.logger.log(!this.haveWarnedAboutLimitedMapping
                ? Level.WARNING : Level.FINE, "Sanitizing and storing "
                + "server descriptor with publication time outside our "
                + "descriptor mapping interval. We might not be able to "
                + "repair references.");
            this.haveWarnedAboutLimitedMapping = true;
          }
          this.descriptorPublicationTimes.add(published);
          scrubbed.append(line + "\n");

        /* Parse the fingerprint to determine the hashed bridge
         * identity. */
        } else if (line.startsWith("opt fingerprint ")) {
          String fingerprint = line.substring(line.startsWith("opt ") ?
              "opt fingerprint".length() : "fingerprint".length()).
              replaceAll(" ", "").toLowerCase();
          byte[] fingerprintBytes = Hex.decodeHex(
              fingerprint.toCharArray());
          hashedBridgeIdentity = DigestUtils.shaHex(fingerprintBytes).
              toLowerCase();
          try {
            scrubbedAddress = scrubIpv4Address(address, fingerprintBytes,
                published);
            if (orAddresses != null) {
              scrubbedOrAddresses = new ArrayList<String>();
              for (String orAddress : orAddresses) {
                String scrubbedOrAddress = scrubOrAddress(orAddress,
                    fingerprintBytes, published);
                if (scrubbedOrAddress != null) {
                  scrubbedOrAddresses.add(scrubbedOrAddress);
                } else {
                  this.logger.warning("Invalid address in line "
                      + "'or-address " + orAddress + "' in bridge server "
                      + "descriptor.  Skipping line!");
                }
              }
            }
          } catch (IOException e) {
            /* There's a persistence problem, so we shouldn't scrub more
             * IP addresses in this execution. */
            return;
          }
          scrubbed.append("opt fingerprint");
          for (int i = 0; i < hashedBridgeIdentity.length() / 4; i++)
            scrubbed.append(" " + hashedBridgeIdentity.substring(4 * i,
                4 * (i + 1)).toUpperCase());
          scrubbed.append("\n");

        /* Replace the contact line (if present) with a generic one. */
        } else if (line.startsWith("contact ")) {
          scrubbed.append("contact somebody\n");

        /* When we reach the signature, we're done. Write the sanitized
         * descriptor to disk below. */
        } else if (line.startsWith("router-signature")) {
          String[] routerLineParts = routerLine.split(" ");
          scrubbedDesc = "router Unnamed " + scrubbedAddress + " "
              + routerLineParts[3] + " " + routerLineParts[4] + " "
              + routerLineParts[5] + "\n";
          if (scrubbedOrAddresses != null) {
            for (String scrubbedOrAddress : scrubbedOrAddresses) {
              scrubbedDesc = scrubbedDesc += "or-address "
                  + scrubbedOrAddress + "\n";
            }
          }
          scrubbedDesc += scrubbed.toString();
          break;

        /* Replace extra-info digest with the one we know from our
         * descriptor mapping (which might be all 0's if we didn't parse
         * the extra-info descriptor before). */
        } else if (line.startsWith("opt extra-info-digest ")) {
          scrubbed.append("opt extra-info-digest "
              + mapping.extraInfoDescriptorIdentifier.toUpperCase()
              + "\n");

        /* Possibly sanitize reject lines if they contain the bridge's own
         * IP address. */
        } else if (line.startsWith("reject ")) {
          if (address != null && line.startsWith("reject " + address)) {
            scrubbed.append("reject " + scrubbedAddress
                + line.substring("reject ".length() + address.length())
                + "\n");
          } else {
            scrubbed.append(line + "\n");
          }

        /* Write the following lines unmodified to the sanitized
         * descriptor. */
        } else if (line.startsWith("accept ")
            || line.startsWith("platform ")
            || line.startsWith("opt protocols ")
            || line.startsWith("uptime ")
            || line.startsWith("bandwidth ")
            || line.startsWith("opt hibernating ")
            || line.equals("opt hidden-service-dir")
            || line.equals("opt caches-extra-info")
            || line.equals("opt allow-single-hop-exits")) {
          scrubbed.append(line + "\n");

        /* Replace node fingerprints in the family line with their hashes
         * and nicknames with Unnamed. */
        } else if (line.startsWith("family ")) {
          StringBuilder familyLine = new StringBuilder("family");
          for (String s : line.substring(7).split(" ")) {
            if (s.startsWith("$")) {
              familyLine.append(" $" + DigestUtils.shaHex(Hex.decodeHex(
                  s.substring(1).toCharArray())).toUpperCase());
            } else {
              familyLine.append(" Unnamed");
            }
          }
          scrubbed.append(familyLine.toString() + "\n");

        /* Skip the purpose line that the bridge authority adds to its
         * cached-descriptors file. */
        } else if (line.startsWith("@purpose ")) {
          continue;

        /* Skip all crypto parts that might leak the bridge's identity
         * fingerprint. */
        } else if (line.startsWith("-----BEGIN ")
            || line.equals("onion-key") || line.equals("signing-key")) {
          skipCrypto = true;

        /* Stop skipping lines when the crypto parts are over. */
        } else if (line.startsWith("-----END ")) {
          skipCrypto = false;

        /* If we encounter an unrecognized line, stop parsing and print
         * out a warning. We might have overlooked sensitive information
         * that we need to remove or replace for the sanitized descriptor
         * version. */
        } else {
          this.logger.fine("Unrecognized line '" + line + "'. Skipping.");
          return;
        }
      }
      br.close();
    } catch (Exception e) {
      this.logger.log(Level.WARNING, "Could not parse server "
          + "descriptor.", e);
      return;
    }

    /* Determine new descriptor digest and write it to descriptor
     * mapping. */
    String scrubbedHash = DigestUtils.shaHex(scrubbedDesc);
    mapping.serverDescriptorIdentifier = scrubbedHash;

    /* Determine filename of sanitized server descriptor. */
    String dyear = mapping.published.substring(0, 4);
    String dmonth = mapping.published.substring(5, 7);
    File newFile = new File(
        this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
        + dyear + "/" + dmonth + "/server-descriptors/"
        + "/" + scrubbedHash.charAt(0) + "/"
        + scrubbedHash.charAt(1) + "/"
        + scrubbedHash);

    /* Write sanitized server descriptor to disk, including all its parent
     * directories. */
    try {
      newFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(newFile));
      bw.write(scrubbedDesc);
      bw.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write sanitized server "
          + "descriptor to disk.", e);
      return;
    }
  }

  /**
   * Sanitizes an extra-info descriptor and writes it to disk. Looks up
   * the bridge identity hash and publication time in the descriptor
   * mapping. If the corresponding server descriptor was sanitized before,
   * it is re-written to include the new extra-info descriptor digest and
   * the publication time is noted down, too, so that all network statuses
   * possibly referencing this extra-info descriptor and its corresponding
   * server descriptor can be re-written at the end of the sanitizing
   * procedure.
   */
  public void sanitizeAndStoreExtraInfoDescriptor(byte[] data) {

    /* Parse descriptor to generate a sanitized version and to look it up
     * in the descriptor mapping. */
    String scrubbedDesc = null, published = null;
    DescriptorMapping mapping = null;
    try {
      BufferedReader br = new BufferedReader(new StringReader(new String(
          data, "US-ASCII")));
      String line = null;
      StringBuilder scrubbed = null;
      String hashedBridgeIdentity = null;
      boolean hasParsedBridgeStatsEndLine = false;
      while ((line = br.readLine()) != null) {

        /* When we have parsed both published and fingerprint line, look
         * up descriptor in the descriptor mapping or create a new one if
         * there is none. */
        if (mapping == null && published != null &&
            hashedBridgeIdentity != null) {
          String mappingKey = hashedBridgeIdentity + "," + published;
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentity,
                published);
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }
        }

        /* Parse bridge identity from extra-info line and replace it with
         * its hash in the sanitized descriptor. */
        if (line.startsWith("extra-info ")) {
          hashedBridgeIdentity = DigestUtils.shaHex(Hex.decodeHex(
              line.split(" ")[2].toCharArray())).toLowerCase();
          scrubbed = new StringBuilder("extra-info Unnamed "
              + hashedBridgeIdentity.toUpperCase() + "\n");

        /* Parse the publication time and add it to the list of descriptor
         * publication times to re-write network statuses at the end of
         * the sanitizing procedure. */
        } else if (line.startsWith("published ")) {
          scrubbed.append(line + "\n");
          published = line.substring("published ".length());
          if (this.bridgeDescriptorMappingsCutOffTimestamp.
              compareTo(published) > 0) {
            this.logger.log(!this.haveWarnedAboutLimitedMapping
                ? Level.WARNING : Level.FINE, "Sanitizing and storing "
                + "extra-info descriptor with publication time outside "
                + "our descriptor mapping interval. We might not be able "
                + "to repair references.");
            this.haveWarnedAboutLimitedMapping = true;
          }

        /* Write bridge-stats lines unmodified to the sanitized
         * descriptor and make sure that there's always a bridge-stats-end
         * line preceding the bridge-ips line. */
        } else if (line.startsWith("bridge-stats-end ")) {
          scrubbed.append(line + "\n");
          hasParsedBridgeStatsEndLine = true;
        } else if (line.startsWith("bridge-ips ")) {
          if (!hasParsedBridgeStatsEndLine) {
            this.logger.fine("bridge-ips line without preceding "
                + "bridge-stats-end line in bridge descriptor.  "
                + "Skipping.");
            return;
          }
          scrubbed.append(line + "\n");

        /* Write the following lines unmodified to the sanitized
         * descriptor. */
        } else if (line.startsWith("write-history ")
            || line.startsWith("read-history ")
            || line.startsWith("geoip-start-time ")
            || line.startsWith("geoip-client-origins ")
            || line.startsWith("geoip-db-digest ")) {
          scrubbed.append(line + "\n");

        /* When we reach the signature, we're done. Write the sanitized
         * descriptor to disk below. */
        } else if (line.startsWith("router-signature")) {
          scrubbedDesc = scrubbed.toString();
          break;
        /* Don't include statistics that should only be contained in relay
         * extra-info descriptors. */
        } else if (line.startsWith("dirreq-") || line.startsWith("cell-")
            || line.startsWith("exit-")) {
          continue;

        /* If we encounter an unrecognized line, stop parsing and print
         * out a warning. We might have overlooked sensitive information
         * that we need to remove or replace for the sanitized descriptor
         * version. */
        } else {
          this.logger.fine("Unrecognized line '" + line + "'. Skipping.");
          return;
        }
      }
      br.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not parse extra-info "
          + "descriptor.", e);
      return;
    } catch (DecoderException e) {
      this.logger.log(Level.WARNING, "Could not parse extra-info "
          + "descriptor.", e);
      return;
    }

    /* Determine new descriptor digest and check if write it to descriptor
     * mapping. */
    String scrubbedDescHash = DigestUtils.shaHex(scrubbedDesc);
    boolean extraInfoDescriptorIdentifierHasChanged =
        !scrubbedDescHash.equals(mapping.extraInfoDescriptorIdentifier);
    mapping.extraInfoDescriptorIdentifier = scrubbedDescHash;
    if (extraInfoDescriptorIdentifierHasChanged &&
        !mapping.serverDescriptorIdentifier.equals(NULL_REFERENCE)) {
      this.rewriteServerDescriptor(mapping);
      this.descriptorPublicationTimes.add(published);
    }

    /* Determine filename of sanitized server descriptor. */
    String dyear = mapping.published.substring(0, 4);
    String dmonth = mapping.published.substring(5, 7);
    File newFile = new File(
        this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
        + dyear + "/" + dmonth + "/extra-infos/"
        + scrubbedDescHash.charAt(0) + "/"
        + scrubbedDescHash.charAt(1) + "/"
        + scrubbedDescHash);

    /* Write sanitized server descriptor to disk, including all its parent
     * directories. */
    try {
      newFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(newFile));
      bw.write(scrubbedDesc);
      bw.close();
    } catch (Exception e) {
      this.logger.log(Level.WARNING, "Could not write sanitized "
          + "extra-info descriptor to disk.", e);
    }
  }

  public void storeSanitizedNetworkStatus(byte[] data, String published) {
    if (this.bridgeDescriptorMappingsCutOffTimestamp.
        compareTo(published) > 0) {
      this.logger.log(!this.haveWarnedAboutLimitedMapping ? Level.WARNING
          : Level.FINE, "Storing sanitized network status with "
          + "publication time outside our descriptor mapping interval. "
          + "We might not be able to repair references.");
      this.haveWarnedAboutLimitedMapping = true;
    }
    String scrubbed = null;
    try {
      String ascii = new String(data, "US-ASCII");
      BufferedReader br2 = new BufferedReader(new StringReader(ascii));
      StringBuilder sb = new StringBuilder();
      String line = null;
      while ((line = br2.readLine()) != null) {
        if (line.startsWith("r ")) {
          String hashedBridgeIdentity = Hex.encodeHexString(
              Base64.decodeBase64(line.split(" ")[2] + "==")).
              toLowerCase();
          String hashedBridgeIdentityBase64 = line.split(" ")[2];
          String readServerDescId = Hex.encodeHexString(
              Base64.decodeBase64(line.split(" ")[3] + "==")).
              toLowerCase();
          String descPublished = line.split(" ")[4] + " "
              + line.split(" ")[5];
          String address = line.split(" ")[6];
          String mappingKey = (hashedBridgeIdentity + ","
              + descPublished).toLowerCase();
          DescriptorMapping mapping = null;
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentity.
                toLowerCase(), descPublished);
            mapping.serverDescriptorIdentifier = readServerDescId;
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }
          String sdi = Base64.encodeBase64String(Hex.decodeHex(
              mapping.serverDescriptorIdentifier.toCharArray())).
              substring(0, 27);
          String orPort = line.split(" ")[7];
          String dirPort = line.split(" ")[8];
          sb.append("r Unnamed "
              + hashedBridgeIdentityBase64 + " " + sdi + " "
              + descPublished + " " + address + " " + orPort + " "
              + dirPort + "\n");
        } else {
          sb.append(line + "\n");
        }
      }
      scrubbed = sb.toString();
      br2.close();
    } catch (DecoderException e) {
      this.logger.log(Level.WARNING, "Could not parse server descriptor "
          + "identifier. This must be a bug.", e);
      return;
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not parse previously "
          + "sanitized network status.", e);
      return;
    }

    /* Check if we need to overwrite the status file on disk. */
    if (new String(data).equals(scrubbed)) {
      this.logger.finer("The bridge network status published " + published
          + " has not changed, so we're not attempting to rewrite it.");
      return;
    }

    try {
      /* Determine file name. */
      String syear = published.substring(0, 4);
      String smonth = published.substring(5, 7);
      String sday = published.substring(8, 10);
      String stime = published.substring(11, 13)
          + published.substring(14, 16)
          + published.substring(17, 19);
      File statusFile = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/" + syear
          + "/" + smonth + "/statuses/" + sday + "/" + syear + smonth
          + sday + "-" + stime + "-"
          + "4A0CCD2DDC7995083D73F5D667100C8A5831F16D");

      /* Create all parent directories to write this network status. */
      statusFile.getParentFile().mkdirs();

      /* Write sanitized network status to disk. */
      BufferedWriter bw = new BufferedWriter(new FileWriter(statusFile));
      bw.write(scrubbed);
      bw.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write previously "
          + "sanitized network status.", e);
      return;
    }
  } 

  public void storeSanitizedServerDescriptor(byte[] data) {
    try {
      String ascii = new String(data, "US-ASCII");
      BufferedReader br2 = new BufferedReader(new StringReader(ascii));
      StringBuilder sb = new StringBuilder();
      String line2 = null, published = null;
      String hashedBridgeIdentity = null;
      DescriptorMapping mapping = null;
      while ((line2 = br2.readLine()) != null) {
        if (mapping == null && published != null &&
            hashedBridgeIdentity != null) {
          String mappingKey = (hashedBridgeIdentity + "," + published).
              toLowerCase();
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentity.
                toLowerCase(), published);
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }
        }
        if (line2.startsWith("router ")) {
          sb.append("router Unnamed " + line2.split(" ")[2] + " "
              + line2.split(" ")[3] + " " + line2.split(" ")[4] + " "
              + line2.split(" ")[5] + "\n");
        } else if (line2.startsWith("published ")) {
          published = line2.substring("published ".length());
          if (this.bridgeDescriptorMappingsCutOffTimestamp.
              compareTo(published) > 0) {
            this.logger.log(!this.haveWarnedAboutLimitedMapping
                ? Level.WARNING : Level.FINE, "Storing sanitized "
                + "server descriptor with publication time outside our "
                + "descriptor mapping interval. We might not be able to "
                + "repair references.");
            this.haveWarnedAboutLimitedMapping = true;
          }
          sb.append(line2 + "\n");
          this.descriptorPublicationTimes.add(published);
        } else if (line2.startsWith("opt fingerprint ")) {
          hashedBridgeIdentity = line2.substring("opt fingerprint".
              length()).replaceAll(" ", "").toLowerCase();
          sb.append(line2 + "\n");
        } else if (line2.startsWith("opt extra-info-digest ")) {
          sb.append("opt extra-info-digest "
              + mapping.extraInfoDescriptorIdentifier.toUpperCase()
              + "\n");
        } else {
          sb.append(line2 + "\n");
        }
      }
      br2.close();
      String scrubbedDesc = sb.toString();
      String scrubbedHash = DigestUtils.shaHex(scrubbedDesc);

      mapping.serverDescriptorIdentifier = scrubbedHash;
      String dyear = published.substring(0, 4);
      String dmonth = published.substring(5, 7);
      File newFile = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
          + dyear + "/" + dmonth + "/server-descriptors/"
          + scrubbedHash.substring(0, 1) + "/"
          + scrubbedHash.substring(1, 2) + "/"
          + scrubbedHash);
      this.logger.finer("Storing server descriptor "
          + newFile.getAbsolutePath());
      newFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          newFile));
      bw.write(scrubbedDesc);
      bw.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not store unsanitized server "
          + "descriptor.", e);
    }
  }

  public void storeSanitizedExtraInfoDescriptor(byte[] data) {
    try {
      String ascii = new String(data, "US-ASCII");
      BufferedReader br2 = new BufferedReader(new StringReader(ascii));
      StringBuilder sb = new StringBuilder();
      String line2 = null, published = null;
      String hashedBridgeIdentity = null;
      DescriptorMapping mapping = null;
      while ((line2 = br2.readLine()) != null) {
        if (mapping == null && published != null &&
            hashedBridgeIdentity != null) {
          String mappingKey = (hashedBridgeIdentity + "," + published).
              toLowerCase();
          if (this.bridgeDescriptorMappings.containsKey(mappingKey)) {
            mapping = this.bridgeDescriptorMappings.get(mappingKey);
          } else {
            mapping = new DescriptorMapping(hashedBridgeIdentity.
                toLowerCase(), published);
            this.bridgeDescriptorMappings.put(mappingKey, mapping);
          }
        }
        if (line2.startsWith("extra-info ")) {
          hashedBridgeIdentity = line2.split(" ")[2];
          sb.append("extra-info Unnamed " + hashedBridgeIdentity
              + "\n");
        } else if (line2.startsWith("published ")) {
          sb.append(line2 + "\n");
          published = line2.substring("published ".length());
          if (this.bridgeDescriptorMappingsCutOffTimestamp.
              compareTo(published) > 0) {
            this.logger.log(!this.haveWarnedAboutLimitedMapping
                ? Level.WARNING : Level.FINE, "Storing sanitized "
                + "extra-info descriptor with publication time outside "
                + "our descriptor mapping interval. We might not be able "
                + "to repair references.");
            this.haveWarnedAboutLimitedMapping = true;
          }
          this.descriptorPublicationTimes.add(published);
        } else {
          sb.append(line2 + "\n");
        }
      }
      br2.close();
      String scrubbedDesc = sb.toString();
      String scrubbedHash = DigestUtils.shaHex(scrubbedDesc);
      mapping.extraInfoDescriptorIdentifier = scrubbedHash;
      String dyear = published.substring(0, 4);
      String dmonth = published.substring(5, 7);
      File newFile = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
          + dyear + "/" + dmonth + "/extra-infos/"
          + scrubbedHash.substring(0, 1) + "/"
          + scrubbedHash.substring(1, 2) + "/"
          + scrubbedHash);
      this.logger.finer("Storing extra-info descriptor "
          + newFile.getAbsolutePath());
      newFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          newFile));
      bw.write(scrubbedDesc);
      bw.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not store sanitized "
          + "extra-info descriptor.", e);
    }
  }

  private void rewriteNetworkStatus(File status, String published) {
    try {
      FileInputStream fis = new FileInputStream(status);
      BufferedInputStream bis = new BufferedInputStream(fis);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      int len;
      byte[] data2 = new byte[1024];
      while ((len = bis.read(data2, 0, 1024)) >= 0) {
        baos.write(data2, 0, len);
      }
      fis.close();
      byte[] allData = baos.toByteArray();
      this.storeSanitizedNetworkStatus(allData, published);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not rewrite network "
          + "status.", e);
    }
  }

  private void rewriteServerDescriptor(DescriptorMapping mapping) {
    try {
      String dyear = mapping.published.substring(0, 4);
      String dmonth = mapping.published.substring(5, 7);
      File serverDescriptorFile = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
          + dyear + "/" + dmonth + "/server-descriptors/"
          + mapping.serverDescriptorIdentifier.substring(0, 1) + "/"
          + mapping.serverDescriptorIdentifier.substring(1, 2) + "/"
          + mapping.serverDescriptorIdentifier);
      FileInputStream fis = new FileInputStream(serverDescriptorFile);
      BufferedInputStream bis = new BufferedInputStream(fis);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      int len;
      byte[] data2 = new byte[1024];
      while ((len = bis.read(data2, 0, 1024)) >= 0) {
        baos.write(data2, 0, len);
      }
      fis.close();
      byte[] allData = baos.toByteArray();
      this.storeSanitizedServerDescriptor(allData);
      serverDescriptorFile.delete();
      this.logger.finer("Deleting server descriptor "
          + serverDescriptorFile.getAbsolutePath());
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not rewrite server "
          + "descriptor.", e);
    }
  }

  /**
   * Rewrite all network statuses that might contain references to server
   * descriptors we added or updated in this execution. This applies to
   * all statuses that have been published up to 24 hours after any added
   * or updated server descriptor.
   */
  public void finishWriting() {

    /* Prepare parsing and formatting timestamps. */
    SimpleDateFormat dateTimeFormat =
         new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    SimpleDateFormat statusFileFormat =
        new SimpleDateFormat("yyyyMMdd-HHmmss");
    statusFileFormat.setTimeZone(TimeZone.getTimeZone("UTC"));    

    /* Iterate over publication timestamps of previously sanitized
     * descriptors. For every publication timestamp, we want to re-write
     * the network statuses that we published up to 24 hours after that
     * descriptor. We keep the timestamp of the last re-written network
     * status in order to make sure we re-writing any network status at
     * most once. */
    this.logger.fine("Rewriting network statuses that might have "
        + "changed.");
    String lastDescriptorPublishedPlus24Hours = "1970-01-01 00:00:00";
    for (String published : this.descriptorPublicationTimes) {
      if (published.compareTo(lastDescriptorPublishedPlus24Hours) <= 0) {
        continue;
      }
      // find statuses 24 hours after published
      SortedSet<File> statusesToRewrite = new TreeSet<File>();
      long publishedTime;
      try {
        publishedTime = dateTimeFormat.parse(published).getTime();
      } catch (ParseException e) {
        this.logger.log(Level.WARNING, "Could not parse publication "
            + "timestamp '" + published + "'. Skipping.", e);
        continue;
      }
      String[] dayOne = dateFormat.format(publishedTime).split("-");

      File publishedDayOne = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
          + dayOne[0] + "/" + dayOne[1] + "/statuses/" + dayOne[2]);
      if (publishedDayOne.exists()) {
        statusesToRewrite.addAll(Arrays.asList(publishedDayOne.
            listFiles()));
      }
      long plus24Hours = publishedTime + 24L * 60L * 60L * 1000L;
      lastDescriptorPublishedPlus24Hours = dateFormat.format(plus24Hours);
      String[] dayTwo = dateFormat.format(plus24Hours).split("-");
      File publishedDayTwo = new File(
          this.sanitizedBridgesDirectory.getAbsolutePath() + "/"
          + dayTwo[0] + "/" + dayTwo[1] + "/statuses/" + dayTwo[2]);
      if (publishedDayTwo.exists()) {
        statusesToRewrite.addAll(Arrays.asList(publishedDayTwo.
            listFiles()));
      }
      for (File status : statusesToRewrite) {
        String statusPublished = status.getName().substring(0, 15);
        long statusTime;
        try {
          statusTime = statusFileFormat.parse(statusPublished).getTime();
        } catch (ParseException e) {
          this.logger.log(Level.WARNING, "Could not parse network "
              + "status publication timestamp '" + published
              + "'. Skipping.", e);
          continue;
        }
        if (statusTime < publishedTime || statusTime > plus24Hours) {
          continue;
        }
        this.rewriteNetworkStatus(status,
            dateTimeFormat.format(statusTime));
      }
    }
    this.logger.fine("Finished rewriting network statuses.");

    /* Write descriptor mappings to disk. */
    try {
      this.logger.fine("Writing descriptor mappings to disk.");
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.bridgeDescriptorMappingsFile));
      int wrote = 0, skipped = 0;
      for (DescriptorMapping mapping :
          this.bridgeDescriptorMappings.values()) {
        String mappingString = mapping.toString();
        if (this.bridgeDescriptorMappingsCutOffTimestamp.
            compareTo(mappingString.split(",")[1]) > 0) {
          skipped++;
        } else {
          wrote++;
          bw.write(mapping.toString() + "\n");
        }
      }
      bw.close();
      this.logger.fine("Finished writing " + wrote + " descriptor "
          + "mappings to disk, skipped " + skipped + ".");
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write descriptor "
          + "mappings to disk.", e);
    }

    /* Delete secrets that we don't need anymore. */
    if (!this.secretsForHashingIPAddresses.isEmpty() &&
        this.secretsForHashingIPAddresses.firstKey().compareTo(
        this.bridgeDescriptorMappingsCutOffTimestamp) < 0) {
      try {
        int kept = 0, deleted = 0;
        BufferedWriter bw = new BufferedWriter(new FileWriter(
            this.bridgeIpSecretsFile));
        for (Map.Entry<String, byte[]> e :
            this.secretsForHashingIPAddresses.entrySet()) {
          if (e.getKey().compareTo(
              this.bridgeDescriptorMappingsCutOffTimestamp) < 0) {
            deleted++;
          } else {
            bw.write(e.getKey() + "," + Hex.encodeHexString(e.getValue())
                + "\n");
            kept++;
          }
        }
        bw.close();
        this.logger.info("Deleted " + deleted + " secrets that we don't "
            + "need anymore and kept " + kept + ".");
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Could not store reduced set of "
            + "secrets to disk! This is a bad sign, better check what's "
            + "going on!", e);
      }
    }
  }
}

