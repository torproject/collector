/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.metrics.collector.Main;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.Key;

import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

public class SanitizeWeblogsTest {

  /** Sample original web server access logs as input for tests. */
  private static final String[][] inputLogs = new String[][] {
      { "metrics.torproject.org-access.log-20191120.gz",
          "0.0.0.0 - - [19/Nov/2019:00:00:00 +0000] "
          + "\"GET /networksize.html HTTP/1.1\" 200 3269 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [19/Nov/2019:00:00:00 +0000] "
          + "\"GET /networksize.png?start=2019-08-21&end=2019-11-19 HTTP/1.1\" "
          + "200 39383 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [19/Nov/2019:00:00:00 +0000] "
          + "\"GET /userstats-relay-country.html HTTP/1.1\" 200 7350 "
          + "\"-\" \"-\" -\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"GET /collector/recent/relay-descriptors/ HTTP/1.1\" 200 10227 "
          + "\"-\" \"-\" -\n" },
      { "metrics.torproject.org-access.log-20191121.gz",
          "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"HEAD /collector/recent/relay-descriptors/microdescs/ "
          + "HTTP/1.1\" 200 - \"-\" \"-\" -\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"HEAD /collector/recent/exit-lists/ HTTP/1.1\" 200 "
          + "- \"-\" \"-\" -\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"GET /collector/archive/bridge-descriptors/extra-infos/ "
          + "HTTP/1.1\" 200 48013 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/cc/sk.png HTTP/1.1\" 200 395 \"-\" \"-\" -\n" },
      { "metrics.torproject.org-access.log-20191122.gz",
          "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/favicon.ico HTTP/1.1\" 200 1150 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/flags/authority.png HTTP/1.1\" 200 325 "
          + "\"https://metrics.torproject.org/rs.html\" \"-\" -\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /news.atom HTTP/1.1\" 200 36362 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [22/Nov/2019:00:00:00 +0000] "
          + "\"GET /onionperf-buildtimes.csv HTTP/1.1\" 200 270336 "
          + "\"-\" \"-\" -\n" },
      { "metrics.torproject.org-access.log-20191123.gz",
          "0.0.0.0 - - [22/Nov/2019:00:00:00 +0000] "
          + "\"GET /userstats-relay-country.html?"
          + "start=2010-01-01&end=2019-11-22&country=vn&events=off HTTP/1.1\" "
          + "200 35517 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [22/Nov/2019:00:00:00 +0000] "
          + "\"GET /userstats-relay-country.png?"
          + "start=2010-01-01&end=2019-11-22&country=vn&events=off HTTP/1.1\" "
          + "200 28041 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [22/Nov/2019:00:00:00 +0000] "
          + "\"GET /userstats-relay-country.png?"
          + "start=2010-01-01&end=2019-11-22&country=vn&events=off HTTP/1.1\" "
          + "200 28041 \"-\" \"-\" -\n"
          + "0.0.0.0 - - [23/Nov/2019:00:00:00 +0000] \"GET / HTTP/1.1\" "
          + "200 3336 \"-\" \"-\" -\n" }
  };

  /** Sanitized web server access logs as output of tests. */
  private static final String[][] outputLogs = new String[][] {
      { "metrics.torproject.org_meronense.torproject.org_"
          + "access.log_20191120.xz",
          "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"GET /collector/archive/bridge-descriptors/extra-infos/ "
          + "HTTP/1.1\" 200 48013\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"GET /collector/recent/relay-descriptors/ HTTP/1.1\" 200 10227\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"HEAD /collector/recent/exit-lists/ HTTP/1.1\" 200 -\n"
          + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
          + "\"HEAD /collector/recent/relay-descriptors/microdescs/ "
          + "HTTP/1.1\" 200 -\n" },
      { "metrics.torproject.org_meronense.torproject.org_"
          + "access.log_20191121.xz",
          "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/cc/sk.png HTTP/1.1\" 200 395\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/favicon.ico HTTP/1.1\" 200 1150\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /images/flags/authority.png HTTP/1.1\" 200 325\n"
          + "0.0.0.0 - - [21/Nov/2019:00:00:00 +0000] "
          + "\"GET /news.atom HTTP/1.1\" 200 36362\n" }
  };

  /** Temporary folder containing all files for this test. */
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  /** Directory containing web server logs to sanitize. */
  private Path inputDirectory;

  /** Directory storing all intermediate state that needs to be preserved
   * between processing runs. */
  private Path statsDirectory;

  /** Directory holding sanitized bridge descriptor files for tarballs. */
  private Path outDirectory;

  /** Directory holding recent sanitized web server logs. */
  private Path recentDirectory;

  /** CollecTor configuration for this test. */
  private Configuration configuration;

  /** Prepares the temporary folder and the various builders for this
   * test. */
  @Before
  public void createTemporaryFolderAndBuilders()
      throws IOException {
    this.inputDirectory = this.temporaryFolder.newFolder("in",
        "webstats", "meronense.torproject.org").toPath();
    this.statsDirectory = this.temporaryFolder.newFolder("stats").toPath();
    this.outDirectory = this.temporaryFolder.newFolder("out").toPath();
    this.recentDirectory = this.temporaryFolder.newFolder("indexed", "recent")
        .toPath();
    this.initializeTestConfiguration();
  }

  /** Initializes a configuration for the bridge descriptor sanitizer. */
  private void initializeTestConfiguration() throws IOException {
    this.configuration = new Configuration();
    this.configuration.load(getClass().getClassLoader().getResourceAsStream(
        Main.CONF_FILE));
    this.configuration.setProperty(Key.WebstatsActivated.name(), "true");
    this.configuration.setProperty(Key.WebstatsLocalOrigins.name(),
        this.inputDirectory.toString());
    this.configuration.setProperty(Key.StatsPath.name(),
        this.statsDirectory.toString());
    this.configuration.setProperty(Key.RecentPath.name(),
        this.recentDirectory.toString());
    this.configuration.setProperty(Key.OutputPath.name(),
        this.outDirectory.toString());
  }

  private void writeInputFiles(String[] ... inputLogs) throws IOException {
    for (String[] inputLog : inputLogs) {
      Path inputLogFile = this.inputDirectory.resolve(inputLog[0]);
      if (!Files.exists(inputLogFile.getParent())) {
        Files.createDirectories(inputLogFile.getParent());
      }
      try (BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(
          new GzipCompressorOutputStream(
          Files.newOutputStream(inputLogFile))))) {
        bw.write(inputLog[1]);
      }
    }
  }

  private void deleteInputFiles(String[] ... deleteLogs) throws IOException {
    for (String[] deleteLog : deleteLogs) {
      Path deleteLogFile = this.inputDirectory.resolve(deleteLog[0]);
      Files.delete(deleteLogFile);
    }
  }

  private void sanitizeWeblogs() {
    SanitizeWeblogs sw = new SanitizeWeblogs(this.configuration);
    sw.startProcessing();
  }

  private void compareResults(String[] ... outputLogs)
      throws DescriptorParseException {
    SortedMap<String, WebServerAccessLog> parsedLogs = new TreeMap<>();
    for (Descriptor descriptor
        : DescriptorSourceFactory.createDescriptorReader()
        .readDescriptors(this.recentDirectory.toFile())) {
      if (!(descriptor instanceof WebServerAccessLog)) {
        fail("Parsed descriptor of unknown type.");
      } else {
        WebServerAccessLog wsal = (WebServerAccessLog) descriptor;
        parsedLogs.put(wsal.getDescriptorFile().getName(), wsal);
      }
    }
    assertEquals(outputLogs.length, parsedLogs.size());
    for (String[] outputLog : outputLogs) {
      String expectedLogFilename = outputLog[0];
      List<String> expectedLogLines = Arrays.asList(outputLog[1].split("\n"));
      assertTrue(parsedLogs.containsKey(expectedLogFilename));
      List<String> actualLogLines = new ArrayList<>();
      parsedLogs.get(expectedLogFilename).logLines()
          .forEach((line) -> actualLogLines.add(line.toString()));
      assertEquals(expectedLogLines, actualLogLines);
    }
  }

  @Test
  public void testSingleRun() throws Exception {
    this.writeInputFiles(inputLogs);
    this.sanitizeWeblogs();
    this.compareResults(outputLogs);
  }

  @Test
  public void testSubsequentRuns() throws Exception {
    for (String[] inputLog : inputLogs) {
      this.writeInputFiles(inputLog);
      this.sanitizeWeblogs();
    }
    this.compareResults(outputLogs);
  }

  @Test
  public void testSubsequentRunsReverseOrder() throws Exception {
    for (int i = inputLogs.length - 1; i >= 0; i--) {
      this.writeInputFiles(inputLogs[i]);
      this.sanitizeWeblogs();
    }
    this.compareResults(outputLogs);
  }

  @Test
  public void testSlidingWindow() throws Exception {
    this.writeInputFiles(inputLogs[0], inputLogs[1], inputLogs[2]);
    this.sanitizeWeblogs();
    this.compareResults(outputLogs[0]);
    this.deleteInputFiles(inputLogs[0]);
    this.writeInputFiles(inputLogs[3]);
    this.sanitizeWeblogs();
    this.compareResults(outputLogs);
  }

  @Test
  public void testSingleDayNoLimit() throws Exception {
    this.configuration.setProperty(Key.WebstatsLimits.name(), "false");
    this.writeInputFiles(new String[][] {
        { "metrics.torproject.org-access.log-20191120.gz",
            "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
            + "\"GET /collector/recent/relay-descriptors/ "
            + "HTTP/1.1\" 200 10227 \"-\" \"-\" -\n"
            + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
            + "\"HEAD /collector/recent/relay-descriptors/microdescs/ "
            + "HTTP/1.1\" 200 - \"-\" \"-\" -\n"
            + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
            + "\"HEAD /collector/recent/exit-lists/ "
            + "HTTP/1.1\" 200 - \"-\" \"-\" -\n"
            + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] "
            + "\"GET /collector/archive/bridge-descriptors/extra-infos/ "
            + "HTTP/1.1\" 200 48013 \"-\" \"-\" -\n" } });
    this.sanitizeWeblogs();
    this.compareResults(outputLogs[0]);
  }

  @Test
  public void testErrorLog() throws Exception {
    this.configuration.setProperty(Key.WebstatsLimits.name(), "false");
    this.writeInputFiles(new String[][] {
        { "metrics.torproject.org-error.log-20191121.gz",
            "[Thu Nov 21 15:13:15.211234 2019] [authz_core:error] "
            + "[pid 12920:tid 139635582793920] [client 127.0.0.1:59912]\n" } });
    this.sanitizeWeblogs();
    this.compareResults();
  }

  @Test
  public void testNonMatchingLines() throws Exception {
    this.configuration.setProperty(Key.WebstatsLimits.name(), "false");
    this.writeInputFiles(new String[][] {
        { "metrics.torproject.org-access.log-20191121.gz",
            "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] \"GET /favicon.ico "
            + "HTTP/1.1\" 404 8903 \"-\" \"-\" -\n"
            + "0.0.0.0 - - [20/Nov/2019:00:00:00 +0000] \"POST /con.php "
            + "HTTP/1.1\" 301 320 \"http://metrics.torproject.org/con.php\" "
            + "\"-\" -\n"
            + "[Thu Nov 21 15:13:15.211234 2019] [authz_core:error] "
            + "[pid 12920:tid 139635582793920] [client 127.0.0.1:59912]\n" } });
    this.sanitizeWeblogs();
    this.compareResults();
  }
}

