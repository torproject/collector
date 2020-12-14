/* Copyright 2012--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.onionperf;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.TorperfResult;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;
import org.torproject.metrics.collector.downloader.Downloader;
import org.torproject.metrics.collector.persist.PersistenceUtils;

import org.apache.commons.compress.utils.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Download OnionPerf files from OnionPerf hosts. */
public class OnionPerfDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      OnionPerfDownloader.class);

  private static final String TORPERF = "torperf";

  private static final String ONIONPERF = "onionperf";

  /** Instantiate the OnionPerf module using the given configuration. */
  public OnionPerfDownloader(Configuration config) {
    super(config);
    this.mapPathDescriptors.put("recent/torperf", TorperfResult.class);
    this.mapPathDescriptors.put("recent/onionperf", TorperfResult.class);
  }

  /** File containing the download history, which is necessary, because
   * OnionPerf does not delete older files, but which enables us to do so. */
  private File onionPerfDownloadedFile;

  /** Full URLs of files downloaded in the current or in past executions. */
  private SortedSet<String> downloadedFiles = new TreeSet<>();

  /** Base URLs of configured OnionPerf hosts. */
  private URL[] onionPerfHosts = null;

  /** Relative URLs of available .tpf files by base URL. */
  private Map<URL, List<String>> tpfFileUrls = new HashMap<>();

  /** Relative URLs of available OnionPerf analysis files by base URL. */
  private Map<URL, List<String>> onionPerfAnalysisFileUrls = new HashMap<>();

  /** Directory for storing archived files. */
  private File archiveDirectory = null;

  /** Directory for storing recent files. */
  private File recentDirectory = null;

  @Override
  public String module() {
    return "onionperf";
  }

  @Override
  protected String syncMarker() {
    return "OnionPerf";
  }

  @Override
  protected void startProcessing() throws ConfigurationException {
    this.onionPerfDownloadedFile =
        new File(config.getPath(Key.StatsPath).toFile(),
        "onionperf-downloaded");
    this.onionPerfHosts = config.getUrlArray(Key.OnionPerfHosts);
    this.readDownloadedOnionPerfFiles();
    this.archiveDirectory = config.getPath(Key.OutputPath).toFile();
    this.recentDirectory = config.getPath(Key.RecentPath).toFile();
    for (URL baseUrl : this.onionPerfHosts) {
      this.downloadFromOnionPerfHost(baseUrl);
    }
    this.writeDownloadedOnionPerfFiles();
    this.cleanUpDirectories();
  }

  private void readDownloadedOnionPerfFiles() {
    if (!this.onionPerfDownloadedFile.exists()) {
      return;
    }
    try (BufferedReader br = new BufferedReader(new FileReader(
          this.onionPerfDownloadedFile))) {
      String line;
      while ((line = br.readLine()) != null) {
        this.downloadedFiles.add(line);
      }
    } catch (IOException e) {
      logger.info("Unable to read download history file '{}'. Ignoring "
          + "download history and downloading all available files.",
          this.onionPerfDownloadedFile.getAbsolutePath());
      this.downloadedFiles.clear();
    }
  }

  private void downloadFromOnionPerfHost(URL baseUrl) {
    logger.info("Downloading from OnionPerf host {}", baseUrl);
    this.downloadOnionPerfDirectoryListing(baseUrl);
    String source = baseUrl.getHost().split("\\.")[0];
    if (this.tpfFileUrls.containsKey(baseUrl)) {
      for (String tpfFileName : this.tpfFileUrls.get(baseUrl)) {
        this.downloadAndParseOnionPerfTpfFile(baseUrl, source, tpfFileName);
      }
    }
    if (this.onionPerfAnalysisFileUrls.containsKey(baseUrl)) {
      for (String onionPerfAnalysisFileName
          : this.onionPerfAnalysisFileUrls.get(baseUrl)) {
        this.downloadAndParseOnionPerfAnalysisFile(baseUrl, source,
            onionPerfAnalysisFileName);
      }
    }
  }

  /** Patterns for links contained in directory listings. */
  private static final Pattern TPF_FILE_URL_PATTERN =
      Pattern.compile(".*<a href=\"([^\"]+\\.tpf)\">.*");

  private static final Pattern ONIONPERF_ANALYSIS_FILE_URL_PATTERN =
      Pattern.compile(
      ".*<a href=\"([0-9-]{10}\\.onionperf\\.analysis\\.json\\.xz)\">.*");

  private void downloadOnionPerfDirectoryListing(URL baseUrl) {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(
        baseUrl.openStream()))) {
      String line;
      while ((line = br.readLine()) != null) {
        Matcher tpfFileMatcher = TPF_FILE_URL_PATTERN.matcher(line);
        if (tpfFileMatcher.matches()
            && !tpfFileMatcher.group(1).startsWith("/")) {
          this.tpfFileUrls.putIfAbsent(baseUrl, new ArrayList<>());
          this.tpfFileUrls.get(baseUrl).add(tpfFileMatcher.group(1));
        }
        Matcher onionPerfAnalysisFileMatcher
            = ONIONPERF_ANALYSIS_FILE_URL_PATTERN.matcher(line);
        if (onionPerfAnalysisFileMatcher.matches()
            && !onionPerfAnalysisFileMatcher.group(1).startsWith("/")) {
          this.onionPerfAnalysisFileUrls.putIfAbsent(baseUrl,
              new ArrayList<>());
          this.onionPerfAnalysisFileUrls.get(baseUrl)
              .add(onionPerfAnalysisFileMatcher.group(1));
        }
      }
    } catch (IOException e) {
      logger.warn("Unable to download directory listing from '{}'.  Skipping "
          + "this OnionPerf host.", baseUrl);
      this.tpfFileUrls.remove(baseUrl);
      this.onionPerfAnalysisFileUrls.remove(baseUrl);
    }
  }

  private static final DateFormat DATE_FORMAT;

  static {
    DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    DATE_FORMAT.setLenient(false);
  }

  private void downloadAndParseOnionPerfTpfFile(URL baseUrl, String source,
      String tpfFileName) {
    URL tpfFileUrl;
    try {
      tpfFileUrl = new URL(baseUrl, tpfFileName);
    } catch (MalformedURLException e1) {
      logger.warn("Unable to put together base URL '{}' and .tpf file path "
          + "'{}' to a URL.  Skipping.", baseUrl, tpfFileName);
      return;
    }

    /* Skip if we successfully downloaded this file before. */
    if (this.downloadedFiles.contains(tpfFileUrl.toString())) {
      return;
    }

    /* Verify file name before downloading: source-filesize-yyyy-MM-dd.tpf */
    String[] tpfFileNameParts = tpfFileName.split("-");
    if (!tpfFileName.startsWith(source + "-")
        || tpfFileName.length() < "s-f-yyyy-MM-dd".length()
        || tpfFileNameParts.length < 5) {
      logger.warn("Invalid .tpf file name '{}{}'.  Skipping.", baseUrl,
          tpfFileName);
      return;
    }
    int fileSize;
    String date;
    try {
      fileSize = Integer.parseInt(
          tpfFileNameParts[tpfFileNameParts.length - 4]);
      date = tpfFileName.substring(tpfFileName.length() - 14,
          tpfFileName.length() - 4);
      DATE_FORMAT.parse(date);
    } catch (NumberFormatException | ParseException e) {
      logger.warn("Invalid .tpf file name '{}{}'.  Skipping.", baseUrl,
          tpfFileName, e);
      return;
    }

    /* Download file contents to temporary file. */
    File tempFile = new File(this.recentDirectory,
        TORPERF + "/." + tpfFileName);
    byte[] downloadedBytes;
    try {
      downloadedBytes = Downloader.downloadFromHttpServer(
          new URL(baseUrl + tpfFileName));
    } catch (IOException e) {
      logger.warn("Unable to download '{}{}'. Skipping.", baseUrl, tpfFileName,
          e);
      return;
    }
    if (null == downloadedBytes) {
      logger.warn("Unable to download '{}{}'. Skipping.", baseUrl, tpfFileName);
      return;
    }
    tempFile.getParentFile().mkdirs();
    try {
      Files.write(tempFile.toPath(), downloadedBytes);
    } catch (IOException e) {
      logger.warn("Unable to write previously downloaded '{}{}' to temporary "
          + "file '{}'. Skipping.", baseUrl, tpfFileName, tempFile, e);
      return;
    }

    /* Validate contained descriptors. */
    DescriptorParser descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
    byte[] rawDescriptorBytes;
    try {
      rawDescriptorBytes = Files.readAllBytes(tempFile.toPath());
    } catch (IOException e) {
      logger.warn("OnionPerf file '{}{}' could not be read.  "
          + "Skipping.", baseUrl, tpfFileName, e);
      tempFile.delete();
      return;
    }
    Iterable<Descriptor> descriptors = descriptorParser.parseDescriptors(
        rawDescriptorBytes, null, tpfFileName);
    String message = null;
    for (Descriptor descriptor : descriptors) {
      if (!(descriptor instanceof TorperfResult)) {
        message = "File contains descriptors other than Torperf results.";
        break;
      }
      TorperfResult torperf = (TorperfResult) descriptor;
      if (!source.equals(torperf.getSource())) {
        message = "File contains Torperf result from another source.";
        break;
      }
      if (fileSize != torperf.getFileSize()) {
        message = "File contains Torperf result from another file size.";
        break;
      }
      if (!date.equals(DATE_FORMAT.format(torperf.getStartMillis()))) {
        message = "File contains Torperf result from another date.";
        break;
      }
    }
    if (null != message) {
      logger.warn("OnionPerf file '{}{}' was found to be invalid: {}.  "
          + "Skipping.", baseUrl, tpfFileName, message);
      tempFile.delete();
      return;
    }

    /* Copy/move files in place. */
    File archiveFile = new File(this.archiveDirectory,
         TORPERF + "/" + date.replaceAll("-", "/") + "/" + tpfFileName);
    archiveFile.getParentFile().mkdirs();
    try {
      Files.copy(tempFile.toPath(), archiveFile.toPath(),
          StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      logger.warn("Unable to copy OnionPerf file {} to {}.  Skipping.",
          tempFile, archiveFile, e);
      tempFile.delete();
      return;
    }
    File recentFile = new File(this.recentDirectory,
        TORPERF + "/" + tpfFileName);
    tempFile.renameTo(recentFile);

    /* Add to download history to avoid downloading it again. */
    this.downloadedFiles.add(baseUrl + tpfFileName);
  }


  private void downloadAndParseOnionPerfAnalysisFile(URL baseUrl, String source,
      String onionPerfAnalysisFileName) {
    URL onionPerfAnalysisFileUrl;
    try {
      onionPerfAnalysisFileUrl = new URL(baseUrl, onionPerfAnalysisFileName);
    } catch (MalformedURLException e1) {
      logger.warn("Unable to put together base URL '{}' and file path '{}' to "
          + "a URL. Skipping.", baseUrl, onionPerfAnalysisFileName);
      return;
    }

    /* Skip if we successfully downloaded this file before. */
    if (this.downloadedFiles.contains(onionPerfAnalysisFileUrl.toString())) {
      return;
    }

    /* Parse date from file name: yyyy-MM-dd.onionperf.analysis.json.xz */
    String date;
    try {
      date = onionPerfAnalysisFileName.substring(0, 10);
      DATE_FORMAT.parse(date);
    } catch (NumberFormatException | ParseException e) {
      logger.warn("Invalid file name '{}{}'. Skipping.", baseUrl,
          onionPerfAnalysisFileName, e);
      return;
    }

    /* Download file contents to temporary file. */
    File tempFile = new File(this.recentDirectory,
        ONIONPERF + "/." + onionPerfAnalysisFileName);
    byte[] downloadedBytes;
    try {
      downloadedBytes = Downloader.downloadFromHttpServer(
          new URL(baseUrl + onionPerfAnalysisFileName));
    } catch (IOException e) {
      logger.warn("Unable to download '{}{}'. Skipping.", baseUrl,
          onionPerfAnalysisFileName, e);
      return;
    }
    if (null == downloadedBytes) {
      logger.warn("Unable to download '{}{}'. Skipping.", baseUrl,
          onionPerfAnalysisFileName);
      return;
    }
    tempFile.getParentFile().mkdirs();
    try {
      Files.write(tempFile.toPath(), downloadedBytes);
    } catch (IOException e) {
      logger.warn("Unable to write previously downloaded '{}{}' to temporary "
          + "file '{}'. Skipping.", baseUrl, onionPerfAnalysisFileName,
          tempFile, e);
      return;
    }

    /* Validate contained descriptors. */
    DescriptorParser descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
    byte[] rawDescriptorBytes;
    try {
      rawDescriptorBytes = IOUtils.toByteArray(
          Files.newInputStream(tempFile.toPath()));
    } catch (IOException e) {
      logger.warn("OnionPerf file '{}{}' could not be read. Skipping.", baseUrl,
          onionPerfAnalysisFileName, e);
      tempFile.delete();
      return;
    }
    Iterable<Descriptor> descriptors = descriptorParser.parseDescriptors(
        rawDescriptorBytes, null, onionPerfAnalysisFileName);
    String message = null;
    for (Descriptor descriptor : descriptors) {
      if (!(descriptor instanceof TorperfResult)) {
        message = "File contains descriptors other than an OnionPerf analysis "
            + "document: " + descriptor.getClass();
        break;
      }
      TorperfResult torperf = (TorperfResult) descriptor;
      if (!source.equals(torperf.getSource())) {
        message = "File contains transfer from another source: "
            + torperf.getSource();
        break;
      }
    }
    if (null != message) {
      logger.warn("OnionPerf file '{}{}' was found to be invalid: {}. "
          + "Skipping.", baseUrl, onionPerfAnalysisFileName, message);
      tempFile.delete();
      return;
    }

    /* Copy/move files in place. */
    File archiveFile = new File(this.archiveDirectory,
        ONIONPERF + "/" + date.replaceAll("-", "/") + "/" + date + "." + source
        + ".onionperf.analysis.json.xz");
    archiveFile.getParentFile().mkdirs();
    try {
      Files.copy(tempFile.toPath(), archiveFile.toPath(),
          StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      logger.warn("Unable to copy OnionPerf file {} to {}. Skipping.",
          tempFile, archiveFile, e);
      tempFile.delete();
      return;
    }
    File recentFile = new File(this.recentDirectory,
        ONIONPERF + "/" + date + "." + source + ".onionperf.analysis.json.xz");
    tempFile.renameTo(recentFile);

    /* Add to download history to avoid downloading it again. */
    this.downloadedFiles.add(baseUrl + onionPerfAnalysisFileName);
  }

  private void writeDownloadedOnionPerfFiles() {
    this.onionPerfDownloadedFile.getParentFile().mkdirs();
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.onionPerfDownloadedFile))) {
      for (String line : this.downloadedFiles) {
        bw.write(line);
        bw.newLine();
      }
    } catch (IOException e) {
      logger.warn("Unable to write download history file '{}'.  This may "
          + "result in ignoring history and downloading all available .tpf "
          + "files in the next execution.",
          this.onionPerfDownloadedFile.getAbsolutePath(), e);
    }
  }

  /** Delete all files from the rsync (out) directories that have not been
   * modified in the last three days (seven weeks). */
  private void cleanUpDirectories() {
    PersistenceUtils.cleanDirectory(
        new File(this.recentDirectory, TORPERF).toPath(),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(
        new File(this.recentDirectory, ONIONPERF).toPath(),
        Instant.now().minus(3, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(
        new File(this.archiveDirectory, TORPERF).toPath(),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
    PersistenceUtils.cleanDirectory(
        new File(this.archiveDirectory, ONIONPERF).toPath(),
        Instant.now().minus(49, ChronoUnit.DAYS).toEpochMilli());
  }
}

