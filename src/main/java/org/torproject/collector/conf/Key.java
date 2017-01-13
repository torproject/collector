/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.conf;

import java.net.URL;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/**
 * Enum containing all the properties keys of the configuration.
 * Specifies the key type.
 */
public enum Key {

  ShutdownGraceWaitMinutes(Long.class),
  RunOnce(Boolean.class),
  ExitlistUrl(URL.class),
  InstanceBaseUrl(String.class),
  ArchivePath(Path.class),
  RecentPath(Path.class),
  OutputPath(Path.class),
  IndexPath(Path.class),
  StatsPath(Path.class),
  SyncPath(Path.class),
  RelaySources(SourceType[].class),
  BridgeSources(SourceType[].class),
  ExitlistSources(SourceType[].class),
  RelayCacheOrigins(String[].class),
  RelayLocalOrigins(Path.class),
  RelaySyncOrigins(URL[].class),
  BridgeSyncOrigins(URL[].class),
  BridgeLocalOrigins(Path.class),
  ExitlistSyncOrigins(URL[].class),
  BridgedescsActivated(Boolean.class),
  BridgedescsOffsetMinutes(Integer.class),
  BridgedescsPeriodMinutes(Integer.class),
  ExitlistsActivated(Boolean.class),
  ExitlistsOffsetMinutes(Integer.class),
  ExitlistsPeriodMinutes(Integer.class),
  RelaydescsActivated(Boolean.class),
  RelaydescsOffsetMinutes(Integer.class),
  RelaydescsPeriodMinutes(Integer.class),
  TorperfActivated(Boolean.class),
  TorperfOffsetMinutes(Integer.class),
  TorperfPeriodMinutes(Integer.class),
  UpdateindexActivated(Boolean.class),
  UpdateindexOffsetMinutes(Integer.class),
  UpdateindexPeriodMinutes(Integer.class),
  CompressRelayDescriptorDownloads(Boolean.class),
  DirectoryAuthoritiesAddresses(String[].class),
  DirectoryAuthoritiesFingerprintsForVotes(String[].class),
  DownloadAllServerDescriptors(Boolean.class),
  DownloadAllExtraInfoDescriptors(Boolean.class),
  KeepDirectoryArchiveImportHistory(Boolean.class),
  ReplaceIpAddressesWithHashes(Boolean.class),
  BridgeDescriptorMappingsLimit(Integer.class),
  TorperfFilesLines(String[].class),
  TorperfHosts(String[][].class);

  private Class clazz;
  private static Set<String> keys;

  /**
   * @param Class of key value.
   */
  Key(Class clazz) {
    this.clazz = clazz;
  }

  public Class keyClass() {
    return clazz;
  }

  /** Verifies, if the given string corresponds to an enum value. */
  public static boolean has(String someKey) {
    if (null == keys) {
      keys = new HashSet<>();
      for (Key key : values()) {
        keys.add(key.name());
      }
    }
    return keys.contains(someKey);
  }

}
