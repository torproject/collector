package org.torproject.collector.conf;

import java.nio.file.Path;

/**
 * Enum containing all the properties keys of the configuration.
 * Specifies the key type.
 */
public enum Key {

  LockFilePath(Path.class),
  ArchivePath(Path.class),
  RecentPath(Path.class),
  IndexPath(Path.class),
  StatsPath(Path.class),
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
  ReplaceIPAddressesWithHashes(Boolean.class),
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
