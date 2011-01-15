/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.text.*;
import java.util.*;
import java.util.logging.*;
import org.apache.commons.codec.digest.*;
import org.apache.commons.codec.binary.*;

/**
 * Parses relay descriptors including network status consensuses and
 * votes, server and extra-info descriptors, and passes the results to the
 * stats handlers, to the archive writer, or to the relay descriptor
 * downloader.
 */
public class RelayDescriptorParser {

  /**
   * Stats file handler that accepts parse results for bridge statistics.
   */
  private BridgeStatsFileHandler bsfh;

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
   * Relay descriptor database importer that stores relay descriptor
   * contents for later evaluation.
   */
  private RelayDescriptorDatabaseImporter rddi;

  private ConsensusHealthChecker chc;

  /**
   * Logger for this class.
   */
  private Logger logger;

  private SimpleDateFormat dateTimeFormat;

  /**
   * Initializes this class.
   */
  public RelayDescriptorParser(BridgeStatsFileHandler bsfh,
      ArchiveWriter aw, RelayDescriptorDatabaseImporter rddi,
      ConsensusHealthChecker chc) {
    this.bsfh = bsfh;
    this.aw = aw;
    this.rddi = rddi;
    this.chc = chc;

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
        int exit = 0, fast = 0, guard = 0, running = 0, stable = 0;
        String validAfterTime = null, nickname = null,
            relayIdentity = null, serverDesc = null, version = null,
            ports = null;
        String fingerprint = null, dirSource = null, address = null;
        long validAfter = -1L, published = -1L, bandwidth = -1L,
            orPort = 0L, dirPort = 0L;
        SortedSet<String> dirSources = new TreeSet<String>();
        SortedSet<String> serverDescriptors = new TreeSet<String>();
        SortedSet<String> hashedRelayIdentities = new TreeSet<String>();
        SortedSet<String> relayFlags = null;
        StringBuilder rawStatusEntry = null;
        while ((line = br.readLine()) != null) {
          if (line.equals("vote-status vote")) {
            isConsensus = false;
          } else if (line.startsWith("valid-after ")) {
            validAfterTime = line.substring("valid-after ".length());
            validAfter = parseFormat.parse(validAfterTime).getTime();
          } else if (line.startsWith("dir-source ")) {
            dirSource = line.split(" ")[2];
          } else if (line.startsWith("vote-digest ")) {
            dirSources.add(dirSource);
          } else if (line.startsWith("fingerprint ")) {
            fingerprint = line.split(" ")[1];
          } else if (line.startsWith("r ")) {
            if (isConsensus && relayIdentity != null &&
                this.rddi != null) {
              byte[] rawDescriptor = rawStatusEntry.toString().getBytes();
              this.rddi.addStatusEntry(validAfter, nickname,
                  relayIdentity, serverDesc, published, address, orPort,
                  dirPort, relayFlags, version, bandwidth, ports,
                  rawDescriptor);
              relayFlags = null;
              version = null;
              bandwidth = -1L;
              ports = null;
            }
            rawStatusEntry = new StringBuilder(line + "\n");
            String[] parts = line.split(" ");
            if (parts.length < 9) {
              this.logger.log(Level.WARNING, "Could not parse r line '"
                  + line + "' in descriptor. Skipping.");
              break;
            }
            String publishedTime = parts[4] + " " + parts[5];
            nickname = parts[1];
            relayIdentity = Hex.encodeHexString(
                Base64.decodeBase64(parts[2] + "=")).
                toLowerCase();
            serverDesc = Hex.encodeHexString(Base64.decodeBase64(
                parts[3] + "=")).toLowerCase();
            serverDescriptors.add(publishedTime + "," + relayIdentity
                + "," + serverDesc);
            hashedRelayIdentities.add(DigestUtils.shaHex(
                Base64.decodeBase64(parts[2] + "=")).
                toUpperCase());
            published = parseFormat.parse(parts[4] + " " + parts[5]).
                getTime();
            address = parts[6];
            orPort = Long.parseLong(parts[7]);
            dirPort = Long.parseLong(parts[8]);
          } else if (line.startsWith("s ") || line.equals("s")) {
            rawStatusEntry.append(line + "\n");
            if (line.contains(" Running")) {
              exit += line.contains(" Exit") ? 1 : 0;
              fast += line.contains(" Fast") ? 1 : 0;
              guard += line.contains(" Guard") ? 1 : 0;
              stable += line.contains(" Stable") ? 1 : 0;
              running++;
            }
            relayFlags = new TreeSet<String>();
            if (line.length() > 2) {
              for (String flag : line.substring(2).split(" ")) {
                relayFlags.add(flag);
              }
            }
          } else if (line.startsWith("v ")) {
            rawStatusEntry.append(line + "\n");
            version = line.substring(2);
          } else if (line.startsWith("w ")) {
            rawStatusEntry.append(line + "\n");
            String[] parts = line.split(" ");
            for (String part : parts) {
              if (part.startsWith("Bandwidth=")) {
                bandwidth = Long.parseLong(part.substring(
                    "Bandwidth=".length()));
              }
            }
          } else if (line.startsWith("p ")) {
            rawStatusEntry.append(line + "\n");
            ports = line.substring(2);
          }
        }
        if (isConsensus) {
          if (this.rddi != null) {
            this.rddi.addConsensus(validAfter, data);
            if (relayIdentity != null) {
              byte[] rawDescriptor = rawStatusEntry.toString().getBytes();
              this.rddi.addStatusEntry(validAfter, nickname,
                  relayIdentity, serverDesc, published, address, orPort,
                  dirPort, relayFlags, version, bandwidth, ports,
                  rawDescriptor);
            }
          }
          if (this.bsfh != null) {
            for (String hashedRelayIdentity : hashedRelayIdentities) {
              this.bsfh.addHashedRelay(hashedRelayIdentity);
            }
          }
          if (this.rdd != null) {
            this.rdd.haveParsedConsensus(validAfterTime, dirSources,
                serverDescriptors);
          }
          if (this.aw != null) {
            this.aw.storeConsensus(data, validAfter);
          }
          if (this.chc != null) {
            this.chc.processConsensus(validAfterTime, data);
          }
        } else {
          if (this.rddi != null) {
            this.rddi.addVote(validAfter, dirSource, data);
          }
          if (this.rdd != null) {
            this.rdd.haveParsedVote(validAfterTime, fingerprint,
                serverDescriptors);
          }
          if (this.aw != null) {
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
            }
          }
          if (this.chc != null) {
            this.chc.processVote(validAfterTime, dirSource, data);
          }
        }
      } else if (line.startsWith("router ")) {
        String platformLine = null, publishedLine = null,
            publishedTime = null, bandwidthLine = null,
            extraInfoDigest = null, relayIdentifier = null;
        String[] parts = line.split(" ");
        String nickname = parts[1];
        String address = parts[2];
        int orPort = Integer.parseInt(parts[3]);
        int dirPort = Integer.parseInt(parts[4]);
        long published = -1L, uptime = -1L;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("platform ")) {
            platformLine = line;
          } else if (line.startsWith("published ")) {
            publishedTime = line.substring("published ".length());
            published = parseFormat.parse(publishedTime).getTime();
          } else if (line.startsWith("opt fingerprint") ||
              line.startsWith("fingerprint")) {
            relayIdentifier = line.substring(line.startsWith("opt ") ?
                "opt fingerprint".length() : "fingerprint".length()).
                replaceAll(" ", "").toLowerCase();
          } else if (line.startsWith("bandwidth ")) {
            bandwidthLine = line;
          } else if (line.startsWith("opt extra-info-digest ") ||
              line.startsWith("extra-info-digest ")) {
            extraInfoDigest = line.startsWith("opt ") ?
                line.split(" ")[2].toLowerCase() :
                line.split(" ")[1].toLowerCase();
          } else if (line.startsWith("uptime ")) {
            uptime = Long.parseLong(line.substring("uptime ".length()));
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
        if (this.rddi != null && digest != null) {
          String[] bwParts = bandwidthLine.split(" ");
          long bandwidthAvg = Long.parseLong(bwParts[1]);
          long bandwidthBurst = Long.parseLong(bwParts[2]);
          long bandwidthObserved = Long.parseLong(bwParts[3]);
          String platform = platformLine.substring("platform ".length());
          this.rddi.addServerDescriptor(digest, nickname, address, orPort,
              dirPort, relayIdentifier, bandwidthAvg, bandwidthBurst,
              bandwidthObserved, platform, published, uptime,
              extraInfoDigest, data);
        }
      } else if (line.startsWith("extra-info ")) {
        String nickname = line.split(" ")[1];
        String publishedTime = null, relayIdentifier = line.split(" ")[2];
        long published = -1L;
        String dir = line.split(" ")[2];
        String statsEnd = null;
        long seconds = -1L;
        List<String> bandwidthHistory = new ArrayList<String>();
        boolean skip = false;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("published ")) {
            publishedTime = line.substring("published ".length());
            published = parseFormat.parse(publishedTime).getTime();
          } else if (line.startsWith("read-history ") ||
              line.startsWith("write-history ") ||
              line.startsWith("dirreq-read-history ") ||
              line.startsWith("dirreq-write-history ")) {
            bandwidthHistory.add(line);
          } else if (line.startsWith("dirreq-stats-end ")) {
            String[] parts = line.split(" ");
            if (parts.length < 5) {
              this.logger.warning("Could not parse dirreq-stats-end "
                  + "line '" + line + "' in descriptor. Skipping.");
              break;
            }
            statsEnd = parts[1] + " " + parts[2];
            seconds = Long.parseLong(parts[3].substring(1));
          } else if (line.startsWith("dirreq-v3-reqs ")
              && line.length() > "dirreq-v3-reqs ".length()) {
            if (this.rddi != null) {
              try {
                int allUsers = 0;
                Map<String, String> obs = new HashMap<String, String>();
                String[] parts = line.substring("dirreq-v3-reqs ".
                    length()).split(",");
                for (String p : parts) {
                  String country = p.substring(0, 2);
                  int users = Integer.parseInt(p.substring(3)) - 4;
                  allUsers += users;
                  obs.put(country, "" + users);
                }
                obs.put("zy", "" + allUsers);
                this.rddi.addDirReqStats(dir, statsEnd, seconds, obs);
              } catch (NumberFormatException e) {
                this.logger.log(Level.WARNING, "Could not parse "
                    + "dirreq-v3-reqs line '" + line + "' in descriptor. "
                    + "Skipping.", e);
                break;
              }
            }
          } else if (line.startsWith("conn-bi-direct ")) {
            if (this.rddi != null) {
              String[] parts = line.split(" ");
              if (parts.length == 6 &&
                  parts[5].split(",").length == 4) {
                try {
                  String connBiDirectStatsEnd = parts[1] + " " + parts[2];
                  long connBiDirectSeconds = Long.parseLong(parts[3].
                      substring(1));
                  String[] parts2 = parts[5].split(",");
                  long below = Long.parseLong(parts2[0]);
                  long read = Long.parseLong(parts2[1]);
                  long write = Long.parseLong(parts2[2]);
                  long both = Long.parseLong(parts2[3]);
                  this.rddi.addConnBiDirect(dir, connBiDirectStatsEnd,
                      connBiDirectSeconds, below, read, write, both);
                } catch (NumberFormatException e) {
                  this.logger.log(Level.WARNING, "Number format "
                      + "exception while parsing conn-bi-direct stats "
                      + "string '" + line + "'. Skipping.", e);
                }
              } else {
                this.logger.warning("Skipping invalid conn-bi-direct "
                    + "stats string '" + line + "'.");
              }
            }
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
        if (this.rddi != null && digest != null) {
          this.rddi.addExtraInfoDescriptor(digest, nickname,
              dir.toLowerCase(), published, data, bandwidthHistory);
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
