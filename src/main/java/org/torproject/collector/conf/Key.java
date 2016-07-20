package org.torproject.collector.conf;

import java.net.URL;
import java.nio.file.Path;

/**
 * Enum containing all the properties keys of the configuration.
 * Specifies the key type.
 */
public enum Key {

  ExitlistOutputDirectory(Path.class),
  ExitlistUrl(URL.class),
  InstanceBaseUrl(String.class),
  LockFilePath(Path.class),
  ArchivePath(Path.class),
  RecentPath(Path.class),
  IndexPath(Path.class),
  StatsPath(Path.class),
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
  BridgeSnapshotsDirectory(Path.class),
  CachedRelayDescriptorsDirectories(String[].class),
  CompressRelayDescriptorDownloads(Boolean.class),
  DirectoryArchivesDirectory(Path.class),
  DirectoryArchivesOutputDirectory(Path.class),
  DownloadRelayDescriptors(Boolean.class),
  DirectoryAuthoritiesAddresses(String[].class),
  DirectoryAuthoritiesFingerprintsForVotes(String[].class),
  DownloadCurrentConsensus(Boolean.class),
  DownloadCurrentMicrodescConsensus(Boolean.class),
  DownloadCurrentVotes(Boolean.class),
  DownloadMissingServerDescriptors(Boolean.class),
  DownloadMissingExtraInfoDescriptors(Boolean.class),
  DownloadMissingMicrodescriptors(Boolean.class),
  DownloadAllServerDescriptors(Boolean.class),
  DownloadAllExtraInfoDescriptors(Boolean.class),
  ImportCachedRelayDescriptors(Boolean.class),
  ImportDirectoryArchives(Boolean.class),
  KeepDirectoryArchiveImportHistory(Boolean.class),
  ReplaceIpAddressesWithHashes(Boolean.class),
  BridgeDescriptorMappingsLimit(Integer.class),
  SanitizedBridgesWriteDirectory(Path.class),
  TorperfOutputDirectory(Path.class),
  TorperfFilesLines(String[].class),
  TorperfSources(String[][].class);

  private Class clazz;

  /**
   * @param Class of key value.
   */
  Key(Class clazz) {
    this.clazz = clazz;
  }

  public Class keyClass() {
    return clazz;
  }

}
