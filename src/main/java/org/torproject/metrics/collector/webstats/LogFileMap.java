/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDate;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * Processes the given path and stores metadata for log files.
 */
public class LogFileMap
    extends TreeMap<String, TreeMap<String, TreeMap<LocalDate, LogMetadata>>> {

  private static final Logger log = LoggerFactory.getLogger(LogFileMap.class);

  /**
   * The map to keep track of the logfiles by virtual host,
   * physical host, and date.
   */
  public LogFileMap(Path startDir) {
    collectFiles(this, startDir);
  }

  private void collectFiles(final LogFileMap logFileMap, Path startDir) {
    try {
      Files.walkFileTree(startDir, new SimpleFileVisitor<Path>() {
        @Override
        public FileVisitResult visitFile(Path path, BasicFileAttributes att)
            throws IOException {
            Optional<LogMetadata> optionalMetadata = LogMetadata.create(path);
          if (optionalMetadata.isPresent()) {
            logFileMap.add(optionalMetadata.get());
          }
          return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path path, IOException ex)
            throws IOException {
          return logIfError(path, ex);
        }

        @Override
        public FileVisitResult postVisitDirectory(Path path, IOException ex)
            throws IOException {
          return logIfError(path, ex);
        }

        private FileVisitResult logIfError(Path path, IOException ex) {
          if (null != ex) {
            log.warn("Cannot process '{}'.", path, ex);
          }
          return FileVisitResult.CONTINUE;
        }
      });
    } catch (IOException ex) {
      log.error("Cannot read directory '{}'.", startDir, ex);
    }
  }

  /** Add log metadata to the map structure. */
  public void add(LogMetadata metadata) {
    TreeMap<String, TreeMap<LocalDate, LogMetadata>> virtualHosts
        = this.get(metadata.virtualHost);
    if (null == virtualHosts) {
      virtualHosts = new TreeMap<>();
      this.put(metadata.virtualHost, virtualHosts);
    }
    TreeMap<LocalDate, LogMetadata> physicalHosts
        = virtualHosts.get(metadata.physicalHost);
    if (null == physicalHosts) {
      physicalHosts = new TreeMap<>();
      virtualHosts.put(metadata.physicalHost, physicalHosts);
    }
    physicalHosts.put(metadata.date, metadata);
  }

  /**
   * Takes the given metadata and returns the LogMetadata for the entry
   * of the next day.
   */
  public Optional<LogMetadata> nextDayLogFor(LogMetadata metadata) {
    TreeMap<String, TreeMap<LocalDate, LogMetadata>> virtualHosts
        = this.get(metadata.virtualHost);
    if (null == virtualHosts) {
      return Optional.empty();
    }
    TreeMap<LocalDate, LogMetadata> physicalHosts
        = virtualHosts.get(metadata.physicalHost);
    if (null == physicalHosts) {
      return Optional.empty();
    }
    return Optional.ofNullable(physicalHosts.get(metadata.date.plusDays(1)));
  }

  /** Returns a stream of all contained log metadata. */
  public Stream<LogMetadata> metadataStream() {
    return this.values().stream()
        .flatMap((virtualHosts) -> virtualHosts.values().stream())
        .flatMap((physicalHosts) -> physicalHosts.values().stream());
  }
}

