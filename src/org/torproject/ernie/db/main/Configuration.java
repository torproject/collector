/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Initialize configuration with hard-coded defaults, overwrite with
 * configuration in config file, if exists, and answer Main.java about our
 * configuration.
 */
public class Configuration {
  private String directoryArchivesOutputDirectory =
      "out/relay-descriptors/";
  private boolean importCachedRelayDescriptors = false;
  private List<String> cachedRelayDescriptorsDirectory =
      new ArrayList<String>(Arrays.asList(
      "in/relay-descriptors/cacheddesc/".split(",")));
  private boolean importDirectoryArchives = false;
  private String directoryArchivesDirectory =
      "in/relay-descriptors/archives/";
  private boolean keepDirectoryArchiveImportHistory = false;
  private boolean replaceIPAddressesWithHashes = false;
  private long limitBridgeDescriptorMappings = -1L;
  private String sanitizedBridgesWriteDirectory =
      "out/bridge-descriptors/";
  private String bridgeSnapshotsDirectory = "in/bridge-descriptors/";
  private boolean downloadRelayDescriptors = false;
  private List<String> downloadFromDirectoryAuthorities = Arrays.asList((
      "86.59.21.38,76.73.17.194:9030,213.115.239.118:443,"
      + "193.23.244.244,208.83.223.34:443,128.31.0.34:9131,"
      + "194.109.206.212,212.112.245.170").split(","));
  private List<String> downloadVotesByFingerprint = Arrays.asList((
      "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4,"
      + "27B6B5996C426270A5C95488AA5BCEB6BCC86956,"
      + "49015F787433103580E3B66A1707A00E60F2D15B,"
      + "585769C78764D58426B8B52B6651A5A71137189A,"
      + "80550987E1D626E3EBA5E5E75A458DE0626D088C,"
      + "D586D18309DED4CD6D57C18FDB97EFA96D330566,"
      + "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58,"
      + "ED03BB616EB2F60BEC80151114BB25CEF515B226,"
      + "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97").split(","));
  private boolean downloadCurrentConsensus = true;
  private boolean downloadCurrentMicrodescConsensus = true;
  private boolean downloadCurrentVotes = true;
  private boolean downloadMissingServerDescriptors = true;
  private boolean downloadMissingExtraInfoDescriptors = true;
  private boolean downloadMissingMicrodescriptors = true;
  private boolean downloadAllServerDescriptors = false;
  private boolean downloadAllExtraInfoDescriptors = false;
  private boolean compressRelayDescriptorDownloads;
  private String assignmentsDirectory = "in/bridge-pool-assignments/";
  private String sanitizedAssignmentsDirectory =
      "out/bridge-pool-assignments/";
  private String torperfOutputDirectory = "out/torperf/";
  private SortedMap<String, String> torperfSources = null;
  private List<String> torperfFiles = null;
  public Configuration() {

    /* Initialize logger. */
    Logger logger = Logger.getLogger(Configuration.class.getName());

    /* Read config file, if present. */
    File configFile = new File("config");
    if (!configFile.exists()) {
      logger.warning("Could not find config file. In the default "
          + "configuration, we are not configured to read data from any "
          + "data source or write data to any data sink. You need to "
          + "create a config file (" + configFile.getAbsolutePath()
          + ") and provide at least one data source and one data sink. "
          + "Refer to the manual for more information.");
      return;
    }
    String line = null;
    boolean containsCachedRelayDescriptorsDirectory = false;
    try {
      BufferedReader br = new BufferedReader(new FileReader(configFile));
      while ((line = br.readLine()) != null) {
        if (line.startsWith("#") || line.length() < 1) {
          continue;
        } else if (line.startsWith("DirectoryArchivesOutputDirectory")) {
          this.directoryArchivesOutputDirectory = line.split(" ")[1];
        } else if (line.startsWith("ImportCachedRelayDescriptors")) {
          this.importCachedRelayDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("CachedRelayDescriptorsDirectory")) {
          if (!containsCachedRelayDescriptorsDirectory) {
            this.cachedRelayDescriptorsDirectory.clear();
            containsCachedRelayDescriptorsDirectory = true;
          }
          this.cachedRelayDescriptorsDirectory.add(line.split(" ")[1]);
        } else if (line.startsWith("ImportDirectoryArchives")) {
          this.importDirectoryArchives = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DirectoryArchivesDirectory")) {
          this.directoryArchivesDirectory = line.split(" ")[1];
        } else if (line.startsWith("KeepDirectoryArchiveImportHistory")) {
          this.keepDirectoryArchiveImportHistory = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("ReplaceIPAddressesWithHashes")) {
          this.replaceIPAddressesWithHashes = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("LimitBridgeDescriptorMappings")) {
          this.limitBridgeDescriptorMappings = Long.parseLong(
              line.split(" ")[1]);
        } else if (line.startsWith("SanitizedBridgesWriteDirectory")) {
          this.sanitizedBridgesWriteDirectory = line.split(" ")[1];
        } else if (line.startsWith("BridgeSnapshotsDirectory")) {
          this.bridgeSnapshotsDirectory = line.split(" ")[1];
        } else if (line.startsWith("DownloadRelayDescriptors")) {
          this.downloadRelayDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadFromDirectoryAuthorities")) {
          this.downloadFromDirectoryAuthorities = new ArrayList<String>();
          for (String dir : line.split(" ")[1].split(",")) {
            // test if IP:port pair has correct format
            if (dir.length() < 1) {
              logger.severe("Configuration file contains directory "
                  + "authority IP:port of length 0 in line '" + line
                  + "'! Exiting!");
              System.exit(1);
            }
            new URL("http://" + dir + "/");
            this.downloadFromDirectoryAuthorities.add(dir);
          }
        } else if (line.startsWith("DownloadVotesByFingerprint")) {
          this.downloadVotesByFingerprint = new ArrayList<String>();
          for (String fingerprint : line.split(" ")[1].split(",")) {
            this.downloadVotesByFingerprint.add(fingerprint);
          }
        } else if (line.startsWith("DownloadCurrentConsensus")) {
          this.downloadCurrentConsensus = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadCurrentMicrodescConsensus")) {
          this.downloadCurrentMicrodescConsensus = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadCurrentVotes")) {
          this.downloadCurrentVotes = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadMissingServerDescriptors")) {
          this.downloadMissingServerDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith(
            "DownloadMissingExtraInfoDescriptors")) {
          this.downloadMissingExtraInfoDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadMissingMicrodescriptors")) {
          this.downloadMissingMicrodescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadAllServerDescriptors")) {
          this.downloadAllServerDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadAllExtraInfoDescriptors")) {
          this.downloadAllExtraInfoDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("CompressRelayDescriptorDownloads")) {
          this.compressRelayDescriptorDownloads = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("AssignmentsDirectory")) {
          this.assignmentsDirectory = line.split(" ")[1];
        } else if (line.startsWith("SanitizedAssignmentsDirectory")) {
          this.sanitizedAssignmentsDirectory = line.split(" ")[1];
        } else if (line.startsWith("TorperfOutputDirectory")) {
          this.torperfOutputDirectory = line.split(" ")[1];
        } else if (line.startsWith("TorperfSource")) {
          if (this.torperfSources == null) {
            this.torperfSources = new TreeMap<String, String>();
          }
          String[] parts = line.split(" ");
          String sourceName = parts[1];
          String baseUrl = parts[2];
          this.torperfSources.put(sourceName, baseUrl);
        } else if (line.startsWith("TorperfFiles")) {
          if (this.torperfFiles == null) {
            this.torperfFiles = new ArrayList<String>();
          }
          String[] parts = line.split(" ");
          if (parts.length != 5) {
            logger.severe("Configuration file contains TorperfFiles "
                + "option with wrong number of values in line '" + line
                + "'! Exiting!");
            System.exit(1);
          }
          this.torperfFiles.add(line);
        } else {
          logger.severe("Configuration file contains unrecognized "
              + "configuration key in line '" + line + "'! Exiting!");
          System.exit(1);
        }
      }
      br.close();
    } catch (ArrayIndexOutOfBoundsException e) {
      logger.severe("Configuration file contains configuration key "
          + "without value in line '" + line + "'. Exiting!");
      System.exit(1);
    } catch (MalformedURLException e) {
      logger.severe("Configuration file contains illegal URL or IP:port "
          + "pair in line '" + line + "'. Exiting!");
      System.exit(1);
    } catch (NumberFormatException e) {
      logger.severe("Configuration file contains illegal value in line '"
          + line + "' with legal values being 0 or 1. Exiting!");
      System.exit(1);
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Unknown problem while reading config "
          + "file! Exiting!", e);
      System.exit(1);
    }
  }
  public String getDirectoryArchivesOutputDirectory() {
    return this.directoryArchivesOutputDirectory;
  }
  public boolean getImportCachedRelayDescriptors() {
    return this.importCachedRelayDescriptors;
  }
  public List<String> getCachedRelayDescriptorDirectory() {
    return this.cachedRelayDescriptorsDirectory;
  }
  public boolean getImportDirectoryArchives() {
    return this.importDirectoryArchives;
  }
  public String getDirectoryArchivesDirectory() {
    return this.directoryArchivesDirectory;
  }
  public boolean getKeepDirectoryArchiveImportHistory() {
    return this.keepDirectoryArchiveImportHistory;
  }
  public boolean getReplaceIPAddressesWithHashes() {
    return this.replaceIPAddressesWithHashes;
  }
  public long getLimitBridgeDescriptorMappings() {
    return this.limitBridgeDescriptorMappings;
  }
  public String getSanitizedBridgesWriteDirectory() {
    return this.sanitizedBridgesWriteDirectory;
  }
  public String getBridgeSnapshotsDirectory() {
    return this.bridgeSnapshotsDirectory;
  }
  public boolean getDownloadRelayDescriptors() {
    return this.downloadRelayDescriptors;
  }
  public List<String> getDownloadFromDirectoryAuthorities() {
    return this.downloadFromDirectoryAuthorities;
  }
  public List<String> getDownloadVotesByFingerprint() {
    return this.downloadVotesByFingerprint;
  }
  public boolean getDownloadCurrentConsensus() {
    return this.downloadCurrentConsensus;
  }
  public boolean getDownloadCurrentMicrodescConsensus() {
    return this.downloadCurrentMicrodescConsensus;
  }
  public boolean getDownloadCurrentVotes() {
    return this.downloadCurrentVotes;
  }
  public boolean getDownloadMissingServerDescriptors() {
    return this.downloadMissingServerDescriptors;
  }
  public boolean getDownloadMissingExtraInfoDescriptors() {
    return this.downloadMissingExtraInfoDescriptors;
  }
  public boolean getDownloadMissingMicrodescriptors() {
    return this.downloadMissingMicrodescriptors;
  }
  public boolean getDownloadAllServerDescriptors() {
    return this.downloadAllServerDescriptors;
  }
  public boolean getDownloadAllExtraInfoDescriptors() {
    return this.downloadAllExtraInfoDescriptors;
  }
  public boolean getCompressRelayDescriptorDownloads() {
    return this.compressRelayDescriptorDownloads;
  }
  public String getAssignmentsDirectory() {
    return this.assignmentsDirectory;
  }
  public String getSanitizedAssignmentsDirectory() {
    return this.sanitizedAssignmentsDirectory;
  }
  public String getTorperfOutputDirectory() {
    return this.torperfOutputDirectory;
  }
  public SortedMap<String, String> getTorperfSources() {
    return this.torperfSources;
  }
  public List<String> getTorperfFiles() {
    return this.torperfFiles;
  }
}

