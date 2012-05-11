/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

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
  private boolean writeDirectoryArchives = false;
  private String directoryArchivesOutputDirectory = "directory-archive/";
  private boolean importCachedRelayDescriptors = false;
  private List<String> cachedRelayDescriptorsDirectory =
      new ArrayList<String>(Arrays.asList("cacheddesc/".split(",")));
  private boolean importDirectoryArchives = false;
  private String directoryArchivesDirectory = "archives/";
  private boolean keepDirectoryArchiveImportHistory = false;
  private boolean writeSanitizedBridges = false;
  private boolean replaceIPAddressesWithHashes = false;
  private long limitBridgeDescriptorMappings = -1L;
  private String sanitizedBridgesWriteDirectory = "sanitized-bridges/";
  private boolean importBridgeSnapshots = false;
  private String bridgeSnapshotsDirectory = "bridge-directories/";
  private boolean downloadRelayDescriptors = false;
  private List<String> downloadFromDirectoryAuthorities = Arrays.asList((
      "86.59.21.38,76.73.17.194:9030,213.115.239.118:443,"
      + "193.23.244.244,208.83.223.34:443,128.31.0.34:9131,"
      + "194.109.206.212,212.112.245.170").split(","));
  private boolean downloadCurrentConsensus = true;
  private boolean downloadCurrentVotes = true;
  private boolean downloadMissingServerDescriptors = true;
  private boolean downloadMissingExtraInfoDescriptors = true;
  private boolean downloadAllServerDescriptors = false;
  private boolean downloadAllExtraInfoDescriptors = false;
  private boolean compressRelayDescriptorDownloads;
  private boolean downloadGetTorStats = false;
  private String getTorStatsUrl = "http://gettor.torproject.org:8080/"
      + "~gettor/gettor_stats.txt";
  private String getTorDirectory = "gettor/";
  private boolean downloadExitList = false;
  private boolean processBridgePoolAssignments = false;
  private String assignmentsDirectory = "assignments/";
  private String sanitizedAssignmentsDirectory = "sanitized-assignments/";
  private boolean processTorperfFiles = false;
  private String torperfOutputDirectory = "torperf/";
  private SortedMap<String, String> torperfSources = null;
  private SortedMap<String, List<String>> torperfDataFiles = null;
  private SortedMap<String, List<String>> torperfExtradataFiles = null;
  private boolean provideFilesViaRsync = false;
  private String rsyncDirectory = "rsync";
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
        } else if (line.startsWith("WriteDirectoryArchives")) {
          this.writeDirectoryArchives = Integer.parseInt(
              line.split(" ")[1]) != 0;
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
        } else if (line.startsWith("WriteSanitizedBridges")) {
          this.writeSanitizedBridges = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("ReplaceIPAddressesWithHashes")) {
          this.replaceIPAddressesWithHashes = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("LimitBridgeDescriptorMappings")) {
          this.limitBridgeDescriptorMappings = Long.parseLong(
              line.split(" ")[1]);
        } else if (line.startsWith("SanitizedBridgesWriteDirectory")) {
          this.sanitizedBridgesWriteDirectory = line.split(" ")[1];
        } else if (line.startsWith("ImportBridgeSnapshots")) {
          this.importBridgeSnapshots = Integer.parseInt(
              line.split(" ")[1]) != 0;
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
        } else if (line.startsWith("DownloadCurrentConsensus")) {
          this.downloadCurrentConsensus = Integer.parseInt(
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
        } else if (line.startsWith("DownloadAllServerDescriptors")) {
          this.downloadAllServerDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadAllExtraInfoDescriptors")) {
          this.downloadAllExtraInfoDescriptors = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("CompressRelayDescriptorDownloads")) {
          this.compressRelayDescriptorDownloads = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("DownloadGetTorStats")) {
          this.downloadGetTorStats = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("GetTorStatsURL")) {
          String newUrl = line.split(" ")[1];
          /* Test if URL has correct format. */
          new URL(newUrl);
          this.getTorStatsUrl = newUrl;
        } else if (line.startsWith("GetTorDirectory")) {
          this.getTorDirectory = line.split(" ")[1];
        } else if (line.startsWith("DownloadExitList")) {
          this.downloadExitList = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("ProcessBridgePoolAssignments")) {
          this.processBridgePoolAssignments = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("AssignmentsDirectory")) {
          this.assignmentsDirectory = line.split(" ")[1];
        } else if (line.startsWith("SanitizedAssignmentsDirectory")) {
          this.sanitizedAssignmentsDirectory = line.split(" ")[1];
        } else if (line.startsWith("ProcessTorperfFiles")) {
          this.processTorperfFiles = Integer.parseInt(line.split(" ")[1])
              != 0;
        } else if (line.startsWith("TorperfOutputDirectory")) {
        } else if (line.startsWith("TorperfSource")) {
          if (this.torperfSources == null) {
            this.torperfSources = new TreeMap<String, String>();
          }
          String[] parts = line.split(" ");
          String sourceName = parts[1];
          String baseUrl = parts[2];
          this.torperfSources.put(sourceName, baseUrl);
        } else if (line.startsWith("TorperfDataFiles")) {
          if (this.torperfDataFiles == null) {
            this.torperfDataFiles = new TreeMap<String, List<String>>();
          }
          String[] parts = line.split(" ");
          String sourceName = parts[1];
          List<String> dataFiles = new ArrayList<String>();
          for (int i = 2; i < parts.length; i++) {
            dataFiles.add(parts[i]);
          }
          this.torperfDataFiles.put(sourceName, dataFiles);
        } else if (line.startsWith("TorperfExtradataFiles")) {
          if (this.torperfExtradataFiles == null) {
            this.torperfExtradataFiles =
                new TreeMap<String, List<String>>();
          }
          String[] parts = line.split(" ");
          String sourceName = parts[1];
          List<String> extradataFiles = new ArrayList<String>();
          for (int i = 2; i < parts.length; i++) {
            extradataFiles.add(parts[i]);
          }
          this.torperfExtradataFiles.put(sourceName, extradataFiles);
        } else if (line.startsWith("ProvideFilesViaRsync")) {
          this.provideFilesViaRsync = Integer.parseInt(
              line.split(" ")[1]) != 0;
        } else if (line.startsWith("RsyncDirectory")) {
          this.rsyncDirectory = line.split(" ")[1];
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

    /** Make some checks if configuration is valid. */
    if (!this.importCachedRelayDescriptors &&
        !this.importDirectoryArchives && !this.downloadRelayDescriptors &&
        !this.importBridgeSnapshots && !this.downloadGetTorStats &&
        !this.downloadExitList && !this.processBridgePoolAssignments &&
        !this.writeDirectoryArchives && !this.writeSanitizedBridges &&
        !this.processTorperfFiles) {
      logger.warning("We have not been configured to read data from any "
          + "data source or write data to any data sink. You need to "
          + "edit your config file (" + configFile.getAbsolutePath()
          + ") and provide at least one data source and one data sink. "
          + "Refer to the manual for more information.");
    }
    if ((this.importCachedRelayDescriptors ||
        this.importDirectoryArchives || this.downloadRelayDescriptors) &&
        !this.writeDirectoryArchives) {
      logger.warning("We are configured to import/download relay "
          + "descriptors, but we don't have a single data sink to write "
          + "relay descriptors to.");
    }
    if (!(this.importCachedRelayDescriptors ||
        this.importDirectoryArchives || this.downloadRelayDescriptors) &&
        this.writeDirectoryArchives) {
      logger.warning("We are configured to write relay descriptor to at "
          + "least one data sink, but we don't have a single data source "
          + "containing relay descriptors.");
    }
    if (this.importBridgeSnapshots && !this.writeSanitizedBridges) {
      logger.warning("We are configured to import/download bridge "
          + "descriptors, but we don't have a single data sink to write "
          + "bridge descriptors to.");
    }
    if (!this.importBridgeSnapshots && this.writeSanitizedBridges) {
      logger.warning("We are configured to write bridge descriptor to at "
          + "least one data sink, but we don't have a single data source "
          + "containing bridge descriptors.");
    }
  }
  public boolean getWriteDirectoryArchives() {
    return this.writeDirectoryArchives;
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
  public boolean getWriteSanitizedBridges() {
    return this.writeSanitizedBridges;
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
  public boolean getImportBridgeSnapshots() {
    return this.importBridgeSnapshots;
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
  public boolean getDownloadCurrentConsensus() {
    return this.downloadCurrentConsensus;
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
  public boolean getDownloadAllServerDescriptors() {
    return this.downloadAllServerDescriptors;
  }
  public boolean getDownloadAllExtraInfoDescriptors() {
    return this.downloadAllExtraInfoDescriptors;
  }
  public boolean getCompressRelayDescriptorDownloads() {
    return this.compressRelayDescriptorDownloads;
  }
  public boolean getDownloadGetTorStats() {
    return this.downloadGetTorStats;
  }
  public String getGetTorStatsUrl() {
    return this.getTorStatsUrl;
  }
  public String getGetTorDirectory() {
    return this.getTorDirectory;
  }
  public boolean getDownloadExitList() {
    return this.downloadExitList;
  }
  public boolean getProcessBridgePoolAssignments() {
    return processBridgePoolAssignments;
  }
  public String getAssignmentsDirectory() {
    return assignmentsDirectory;
  }
  public String getSanitizedAssignmentsDirectory() {
    return sanitizedAssignmentsDirectory;
  }
  public boolean getProcessTorperfFiles() {
    return this.processTorperfFiles;
  }
  public String getTorperfOutputDirectory() {
    return this.torperfOutputDirectory;
  }
  public SortedMap<String, String> getTorperfSources() {
    return this.torperfSources;
  }
  public SortedMap<String, List<String>> getTorperfDataFiles() {
    return this.torperfDataFiles;
  }
  public SortedMap<String, List<String>> getTorperfExtradataFiles() {
    return this.torperfExtradataFiles;
  }
  public boolean getProvideFilesViaRsync() {
    return this.provideFilesViaRsync;
  }
  public String getRsyncDirectory() {
    return this.rsyncDirectory;
  }
}

