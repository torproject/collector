/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import static org.torproject.descriptor.log.WebServerAccessLogImpl.MARKER;

import org.torproject.descriptor.internal.FileType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogMetadata {

  private static final Logger log
      = LoggerFactory.getLogger(LogMetadata.class);

  /** The mandatory web server log descriptor file name pattern. */
  public static final Pattern filenamePattern
      = Pattern.compile("(\\S*)-" + MARKER
      + "-(\\d{8})(?:\\.?)([a-zA-Z0-9]+)$");

  /** The path of the log file to be imported. */
  public final Path path;

  /** The date the log entries were created. */
  public final LocalDate date;

  /** The log's compression type. */
  public final FileType fileType;

  /** The name of the physical host. */
  public final String physicalHost;

  /** The name of the virtual host. */
  public final String virtualHost;

  private LogMetadata(Path logPath, String physicalHost, String virtualHost,
      LocalDate logDate, FileType fileType) {
    this.path = logPath;
    this.date = logDate;
    this.fileType = fileType;
    this.physicalHost = physicalHost;
    this.virtualHost = virtualHost;
  }

  /**
   * Only way to create a LogMetadata object from a given log path.
   */
  public static Optional<LogMetadata> create(Path logPath) {
    LogMetadata metadata = null;
    try {
      Path parentPath = logPath.getName(logPath.getNameCount() - 2);
      Path file = logPath.getFileName();
      if (null != parentPath && null != file) {
        String physicalHost = parentPath.toString();
        Matcher mat = filenamePattern.matcher(file.toString());
        if (mat.find()) {
          String virtualHost = mat.group(1);
          // verify date given
          LocalDate logDate
              = LocalDate.parse(mat.group(2), DateTimeFormatter.BASIC_ISO_DATE);
          if (null == virtualHost || null == physicalHost || null == logDate
              || virtualHost.isEmpty() || physicalHost.isEmpty()) {
            log.debug("Non-matching file encountered: '{}/{}'.",
                parentPath, file);
          } else {
            metadata = new LogMetadata(logPath, physicalHost, virtualHost,
                logDate, FileType.findType(mat.group(3)));
          }
        }
      }
    } catch (Throwable ex) {
      metadata = null;
      log.debug("Problem parsing path '{}'.", logPath, ex);
    }
    return Optional.ofNullable(metadata);
  }
}

