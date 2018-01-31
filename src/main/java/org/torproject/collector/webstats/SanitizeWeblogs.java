/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.webstats;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.conf.SourceType;
import org.torproject.collector.cron.CollecTorMain;

import org.torproject.collector.persist.PersistenceUtils;
import org.torproject.collector.persist.WebServerAccessLogPersistence;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.descriptor.log.InternalLogDescriptor;
import org.torproject.descriptor.log.InternalWebServerAccessLog;
import org.torproject.descriptor.log.Method;
import org.torproject.descriptor.log.WebServerAccessLogImpl;
import org.torproject.descriptor.log.WebServerAccessLogLine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This module processes web-logs for CollecTor according to the weblog
 * sanitation specification published on metrics.torproject.org</p>
 */
public class SanitizeWeblogs extends CollecTorMain {

  private static final Logger log =
      LoggerFactory.getLogger(SanitizeWeblogs.class);
  private static final int LIMIT = 2;

  private static final String WEBSTATS = "webstats";
  private String outputPathName;
  private String recentPathName;
  private boolean limits;

  /**
   * Possibly privacy impacting data is replaced by dummy data producing a
   * log-file (or files) that confirm(s) to Apache's Combined Log Format.
   */
  public SanitizeWeblogs(Configuration conf) {
    super(conf);
    this.mapPathDescriptors.put("recent/webstats", WebServerAccessLog.class);
  }

  @Override
  public String module() {
    return WEBSTATS;
  }

  @Override
  protected String syncMarker() {
    return "Webstats";
  }

  @Override
  protected void startProcessing() throws ConfigurationException {
    try {
      Files.createDirectories(this.config.getPath(Key.OutputPath));
      Files.createDirectories(this.config.getPath(Key.RecentPath));
      this.outputPathName = this.config.getPath(Key.OutputPath).toString();
      this.recentPathName = this.config.getPath(Key.RecentPath).toString();
      this.limits = this.config.getBool(Key.WebstatsLimits);
      Set<SourceType> sources = this.config.getSourceTypeSet(
          Key.WebstatsSources);
      if (sources.contains(SourceType.Local)) {
        findCleanWrite(this.config.getPath(Key.WebstatsLocalOrigins));
        PersistenceUtils.cleanDirectory(this.config.getPath(Key.RecentPath));
      }
    } catch (Exception e) {
      log.error("Cannot sanitize web-logs: " + e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  private void findCleanWrite(Path dir) {
    LogFileMap fileMapIn = new LogFileMap(dir);
    log.info("Found log files for {} virtual hosts.", fileMapIn.size());
    for (Map.Entry<String,TreeMap<String,TreeMap<LocalDate,LogMetadata>>>
             virtualEntry : fileMapIn.entrySet()) {
      String virtualHost = virtualEntry.getKey();
      for (Map.Entry<String, TreeMap<LocalDate, LogMetadata>> physicalEntry
          : virtualEntry.getValue().entrySet()) {
        String physicalHost = physicalEntry.getKey();
        log.info("Processing logs for {} on {}.", virtualHost, physicalHost);
        Map<LocalDate, List<WebServerAccessLogLine>> linesByDate
            = physicalEntry.getValue().values().stream().parallel()
            .flatMap((LogMetadata metadata)
                -> lineStream(metadata).filter((line) -> line.isValid()))
            .collect(Collectors.groupingBy(WebServerAccessLogLine::getDate,
                Collectors.toList()));
        LocalDate[] interval = determineInterval(linesByDate.keySet());
        linesByDate.entrySet().stream()
            .filter((entry) -> entry.getKey().isAfter(interval[0])
              && entry.getKey().isBefore(interval[1])).parallel()
            .forEach((entry) -> storeSanitized(virtualHost, physicalHost,
              entry.getKey(), entry.getValue()));
      }
    }
  }

  private void storeSanitized(String virtualHost, String physicalHost,
      LocalDate date, List<WebServerAccessLogLine> lines) {
    String name = new StringJoiner(InternalLogDescriptor.SEP)
        .add(virtualHost).add(physicalHost)
        .add(InternalWebServerAccessLog.MARKER)
        .add(date.format(DateTimeFormatter.BASIC_ISO_DATE)).toString();
    log.debug("Sanitizing {}.", name);
    List<String> retainedLines = lines
        .stream().parallel().map((line) -> sanitize(line, date))
        .filter((line) -> line.isPresent()).map((line) -> line.get())
        .collect(Collectors.toList());
    retainedLines.sort(null);
    try {
      WebServerAccessLogPersistence walp
          = new WebServerAccessLogPersistence(
          new WebServerAccessLogImpl(retainedLines, name));
      log.debug("Storing {}.", name);
      walp.storeOut(this.outputPathName);
      walp.storeRecent(this.recentPathName);
    } catch (DescriptorParseException dpe) {
      log.error("Cannot store log desriptor {}.", name, dpe);
    }
  }

  static Optional<String> sanitize(WebServerAccessLogLine logLine,
      LocalDate date) {
    if (!logLine.isValid()
        || !(Method.GET == logLine.getMethod()
             || Method.HEAD == logLine.getMethod())
        || !logLine.getProtocol().startsWith("HTTP")
        || 400 == logLine.getResponse() || 404 == logLine.getResponse()) {
      return Optional.empty();
    }
    if (!logLine.getIp().startsWith("0.0.0.")) {
      logLine.setIp("0.0.0.0");
    }
    int queryStart = logLine.getRequest().indexOf("?");
    if (queryStart > 0) {
      logLine.setRequest(logLine.getRequest().substring(0, queryStart));
    }
    return Optional.of(logLine.toLogString());
  }

  LocalDate[] determineInterval(Set<LocalDate> dates) {
    SortedSet<LocalDate> sorted = new TreeSet<>();
    sorted.addAll(dates);
    if (this.limits) {
      for (int i = 0; i < LIMIT - 1; i++) {
        sorted.remove(sorted.last());
      }
    }
    if (sorted.isEmpty()) {
      return new LocalDate[]{LocalDate.MAX, LocalDate.MIN};
    }
    if (!this.limits) {
      sorted.add(sorted.first().minusDays(1));
      sorted.add(sorted.last().plusDays(1));
    }
    return new LocalDate[]{sorted.first(), sorted.last()};
  }

  private Stream<WebServerAccessLogLine> lineStream(LogMetadata metadata) {
    log.debug("Processing file {}.", metadata.path);
    try (BufferedReader br
        = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(
         metadata.fileType.decompress(Files.readAllBytes(metadata.path)))))) {
      return br.lines()
          .map((String line) -> WebServerAccessLogLine.makeLine(line))
          .collect(Collectors.toList()).stream();
    } catch (Exception ex) {
      log.debug("Skipping log-file {}.", metadata.path, ex);
    }
    return Stream.empty();
  }

}

