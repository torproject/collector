/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.webstats;

import static java.util.stream.Collectors.counting;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.groupingByConcurrent;
import static java.util.stream.Collectors.reducing;
import static java.util.stream.Collectors.summingLong;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.conf.SourceType;
import org.torproject.collector.cron.CollecTorMain;

import org.torproject.collector.persist.PersistenceUtils;
import org.torproject.collector.persist.WebServerAccessLogPersistence;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.Method;
import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.descriptor.internal.FileType;
import org.torproject.descriptor.log.InternalLogDescriptor;
import org.torproject.descriptor.log.InternalWebServerAccessLog;
import org.torproject.descriptor.log.WebServerAccessLogImpl;
import org.torproject.descriptor.log.WebServerAccessLogLine;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
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
        log.info("Processing logs using batch value {}.", BATCH);
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
        Map<LocalDate, Map<String, Long>> linesByDate
            = physicalEntry.getValue().values().stream().parallel()
            .flatMap(metadata -> sanitzedLineStream(metadata).entrySet()
            .stream())
            .collect(groupingBy(Map.Entry::getKey,
              reducing(Collections.emptyMap(), Map.Entry::getValue,
                (e1, e2) -> Stream.concat(e1.entrySet().stream(), e2.entrySet()
                  .stream())
                  .collect(groupingByConcurrent(Map.Entry::getKey,
                  summingLong(Map.Entry::getValue))))));
        LocalDate[] interval = determineInterval(linesByDate.keySet());
        linesByDate.entrySet().stream()
            .filter((entry) -> entry.getKey().isAfter(interval[0])
              && entry.getKey().isBefore(interval[1])).parallel()
            .forEach((entry) -> storeSortedAndForget(virtualHost, physicalHost,
              entry.getKey(), entry.getValue()));
      }
    }
  }

  private void storeSortedAndForget(String virtualHost, String physicalHost,
      LocalDate date, Map<String, Long> lineCounts) {
    String name = new StringJoiner(InternalLogDescriptor.SEP)
        .add(virtualHost).add(physicalHost)
        .add(InternalWebServerAccessLog.MARKER)
        .add(date.format(DateTimeFormatter.BASIC_ISO_DATE))
        .toString() + "." + FileType.XZ.name().toLowerCase();
    log.debug("Storing {}.", name);
    Map<String, Long> retainedLines = new TreeMap<>(lineCounts);
    lineCounts.clear(); // not needed anymore
    try {
      WebServerAccessLogPersistence walp
          = new WebServerAccessLogPersistence(
          new WebServerAccessLogImpl(toCompressedBytes(retainedLines),
          name, false));
      log.debug("Storing {}.", name);
      walp.storeOut(this.outputPathName);
      walp.storeRecent(this.recentPathName);
    } catch (DescriptorParseException dpe) {
      log.error("Cannot store log desriptor {}.", name, dpe);
    } catch (Throwable th) { // catch all else
      log.error("Serious problem.  Cannot store log desriptor {}.", name, th);
    }
  }

  private static final int BATCH = 100_000;

  static byte[] toCompressedBytes(Map<String, Long> lines)
    throws DescriptorParseException {
    try (ByteArrayOutputStream baos =  new ByteArrayOutputStream();
         OutputStream os = FileType.XZ.outputStream(baos)) {
      for (Map.Entry<String, Long> entry : lines.entrySet()) {
        long count = entry.getValue();
        byte[] batch = bytesFor(entry.getKey(), BATCH);
        while (count > 0) {
          if (count > BATCH) {
            os.write(batch);
            count -= BATCH;
          } else {
            os.write(bytesFor(entry.getKey(), count));
            break;
          }
        }
      }
      os.flush();
      os.close();
      return baos.toByteArray();
    } catch (Exception ex) {
      throw new DescriptorParseException(ex.getMessage());
    }
  }

  private static byte[] bytesFor(String line, long times) {
    return Stream.of(line).limit(times)
        .collect(Collectors.joining("\n", "", "\n")).getBytes();
  }

  static Optional<WebServerAccessLogLine>
      sanitize(WebServerAccessLogLine logLine) {
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
    return Optional.of(logLine);
  }

  LocalDate[] determineInterval(Set<LocalDate> dates) {
    if (dates.isEmpty()) { // return the empty interval
      return new LocalDate[]{LocalDate.MAX, LocalDate.MIN};
    }
    SortedSet<LocalDate> sorted = new TreeSet<>();
    sorted.addAll(dates);
    if (this.limits) {
      for (int i = 0; i < LIMIT - 1; i++) {
        sorted.remove(sorted.last());
      }
    }
    if (sorted.isEmpty()) { // return the empty interval
      return new LocalDate[]{LocalDate.MAX, LocalDate.MIN};
    }
    if (!this.limits) {
      sorted.add(sorted.first().minusDays(1));
      sorted.add(sorted.last().plusDays(1));
    }
    return new LocalDate[]{sorted.first(), sorted.last()};
  }

  private static final int LISTLIMIT = Integer.MAX_VALUE / 2;

  private Map<LocalDate, Map<String, Long>>
      sanitzedLineStream(LogMetadata metadata) {
    log.debug("Processing file {}.", metadata.path);
    try (BufferedReader br
        = new BufferedReader(new InputStreamReader(
         metadata.fileType.decompress(Files.newInputStream(metadata.path))))) {
      List<List<WebServerAccessLogLine>> lists = new ArrayList<>();
      List<WebServerAccessLogLine> currentList = new ArrayList<>();
      lists.add(currentList);
      String lineStr = br.readLine();
      int count = 0;
      while (null != lineStr) {
        WebServerAccessLogLine wsal = WebServerAccessLogLine.makeLine(lineStr);
        if (wsal.isValid()) {
          currentList.add(wsal);
          count++;
        }
        if (count >= LISTLIMIT) {
          currentList = new ArrayList<>();
          lists.add(currentList);
          count = 0;
        }
        lineStr = br.readLine();
      }
      br.close();
      return lists.parallelStream()
          .map(list -> list.stream()
              .map(line -> sanitize(line))
              .filter(line -> line.isPresent())
              .map(line -> line.get())
              .collect(groupingBy(WebServerAccessLogLine::getDate,
                  groupingBy(WebServerAccessLogLine::toLogString, counting()))))
          .flatMap(map -> map.entrySet().stream()).parallel()
          .collect(groupingByConcurrent(Map.Entry::getKey,
              reducing(Collections.emptyMap(), Map.Entry::getValue,
                (e1, e2) -> Stream.concat(e1.entrySet().stream(),
                    e2.entrySet().stream()).parallel()
                    .collect(groupingByConcurrent(Map.Entry::getKey,
                        summingLong(Map.Entry::getValue))))));
    } catch (Exception ex) {
      log.debug("Skipping log-file {}.", metadata.path, ex);
    }
    return Collections.emptyMap();
  }

}

