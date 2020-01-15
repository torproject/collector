/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import org.torproject.descriptor.BandwidthFile;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgePoolAssignment;
import org.torproject.descriptor.BridgedbMetrics;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.DirectoryKeyCertificate;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.ExtraInfoDescriptor;
import org.torproject.descriptor.Microdescriptor;
import org.torproject.descriptor.RelayDirectory;
import org.torproject.descriptor.RelayNetworkStatus;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.ServerDescriptor;
import org.torproject.descriptor.SnowflakeStats;
import org.torproject.descriptor.TorperfResult;
import org.torproject.descriptor.UnparseableDescriptor;
import org.torproject.descriptor.WebServerAccessLog;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Callable;

/**
 * Callable task that indexes a given descriptor file.
 */
class IndexerTask implements Callable<FileNode> {

  /**
   * Class logger.
   */
  private static final Logger logger
      = LoggerFactory.getLogger(IndexerTask.class);

  /**
   * Formatter for all timestamps found in {@code index.json}.
   */
  private static DateTimeFormatter dateTimeFormatter = DateTimeFormatter
      .ofPattern("uuuu-MM-dd HH:mm").withZone(ZoneOffset.UTC);

  /**
   * Path to the descriptor file to index.
   */
  private Path path;

  /**
   * Index results object, which starts out empty and gets populated as indexing
   * proceeds.
   */
  private FileNode indexResult;

  /**
   * Create a new instance to parse the given descriptor file, but don't start
   * parsing just yet.
   *
   * @param path Descriptor file to index.
   */
  IndexerTask(Path path) {
    this.path = path;
  }

  /**
   * Index the given file and return index results when done.
   *
   * @return Index results.
   * @throws IOException Thrown if an I/O error occurs.
   */
  @Override
  public FileNode call() throws IOException {
    this.indexResult = new FileNode();
    this.requestBasicFileAttributes();
    this.computeFileDigest();
    this.parseDescriptorFile();
    return this.indexResult;
  }

  /**
   * Request and store basic file attributes like file name, last-modified time,
   * and size.
   *
   * @throws IOException Thrown if an I/O error occurs.
   */
  private void requestBasicFileAttributes() throws IOException {
    this.indexResult.path = this.path.getFileName().toString();
    this.indexResult.lastModified = dateTimeFormatter
        .format(Files.getLastModifiedTime(this.path).toInstant());
    this.indexResult.size = Files.size(this.path);
  }

  /**
   * Compute and store the file's SHA-256 digest.
   *
   * @throws IOException Thrown if an I/O error occurs.
   */
  private void computeFileDigest() throws IOException {
    try (InputStream stream = Files.newInputStream(this.path)) {
      this.indexResult.sha256
          = Base64.encodeBase64String(DigestUtils.sha256(stream));
    }
  }

  /**
   * Parse the descriptor file to extract contained descriptor types and first
   * and last published time.
   */
  private void parseDescriptorFile() {
    Long firstPublishedMillis = null;
    Long lastPublishedMillis = null;
    this.indexResult.types = new TreeSet<>();
    SortedSet<String> unknownDescriptorSubclasses = new TreeSet<>();
    for (Descriptor descriptor : DescriptorSourceFactory
        .createDescriptorReader().readDescriptors(this.path.toFile())) {
      if (descriptor instanceof UnparseableDescriptor) {
        /* Skip unparseable descriptor. */
        continue;
      }
      for (String annotation : descriptor.getAnnotations()) {
        if (annotation.startsWith("@type ")) {
          this.indexResult.types.add(annotation.substring(6));
        }
      }
      Long publishedMillis;
      if (descriptor instanceof BandwidthFile) {
        BandwidthFile bandwidthFile = (BandwidthFile) descriptor;
        LocalDateTime fileCreatedOrTimestamp
            = bandwidthFile.fileCreated().isPresent()
            ? bandwidthFile.fileCreated().get()
            : bandwidthFile.timestamp();
        publishedMillis = fileCreatedOrTimestamp
            .toInstant(ZoneOffset.UTC).toEpochMilli();
      } else if (descriptor instanceof BridgeNetworkStatus) {
        publishedMillis = ((BridgeNetworkStatus) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof BridgePoolAssignment) {
        publishedMillis = ((BridgePoolAssignment) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof BridgedbMetrics) {
        publishedMillis = ((BridgedbMetrics) descriptor)
            .bridgedbMetricsEnd().toInstant(ZoneOffset.UTC).toEpochMilli();
      } else if (descriptor instanceof DirectoryKeyCertificate) {
        publishedMillis = ((DirectoryKeyCertificate) descriptor)
            .getDirKeyPublishedMillis();
      } else if (descriptor instanceof ExitList) {
        publishedMillis = ((ExitList) descriptor)
            .getDownloadedMillis();
      } else if (descriptor instanceof ExtraInfoDescriptor) {
        publishedMillis = ((ExtraInfoDescriptor) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof Microdescriptor) {
        /* Microdescriptors don't contain useful timestamps for this purpose,
         * but we already knew that, so there's no need to log a warning
         * further down below. */
        continue;
      } else if (descriptor instanceof RelayDirectory) {
        publishedMillis = ((RelayDirectory) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof RelayNetworkStatus) {
        publishedMillis = ((RelayNetworkStatus) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof RelayNetworkStatusConsensus) {
        publishedMillis = ((RelayNetworkStatusConsensus) descriptor)
            .getValidAfterMillis();
      } else if (descriptor instanceof RelayNetworkStatusVote) {
        publishedMillis = ((RelayNetworkStatusVote) descriptor)
            .getValidAfterMillis();
      } else if (descriptor instanceof ServerDescriptor) {
        publishedMillis = ((ServerDescriptor) descriptor)
            .getPublishedMillis();
      } else if (descriptor instanceof SnowflakeStats) {
        publishedMillis = ((SnowflakeStats) descriptor)
            .snowflakeStatsEnd().toInstant(ZoneOffset.UTC).toEpochMilli();
      } else if (descriptor instanceof TorperfResult) {
        publishedMillis = ((TorperfResult) descriptor)
            .getStartMillis();
      } else if (descriptor instanceof WebServerAccessLog) {
        publishedMillis = ((WebServerAccessLog) descriptor)
            .getLogDate().atStartOfDay(ZoneOffset.UTC)
            .toInstant().toEpochMilli();
      } else {
        /* Skip published timestamp if descriptor type is unknown or doesn't
         * contain such a timestamp. */
        unknownDescriptorSubclasses.add(
            descriptor.getClass().getSimpleName());
        continue;
      }
      if (null == firstPublishedMillis
          || publishedMillis < firstPublishedMillis) {
        firstPublishedMillis = publishedMillis;
      }
      if (null == lastPublishedMillis
          || publishedMillis > lastPublishedMillis) {
        lastPublishedMillis = publishedMillis;
      }
    }
    if (!unknownDescriptorSubclasses.isEmpty()) {
      logger.warn("Ran into unknown/unexpected Descriptor subclass(es) in "
          + "{}: {}. Ignoring for index.json, but maybe worth looking into.",
          this.path, unknownDescriptorSubclasses);
    }
    this.indexResult.firstPublished = null == firstPublishedMillis ? null
        : dateTimeFormatter.format(Instant.ofEpochMilli(firstPublishedMillis));
    this.indexResult.lastPublished = null == lastPublishedMillis ? null
        : dateTimeFormatter.format(Instant.ofEpochMilli(lastPublishedMillis));
  }
}

