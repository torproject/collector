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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Download download .tpf files from OnionPerf hosts. */
public class OnionPerfDownloader extends CollecTorMain {

  private static final Logger logger = LoggerFactory.getLogger(
      OnionPerfDownloader.class);

  private static final String TORPERF = "torperf";

  /** Instantiate the OnionPerf module using the given configuration. */
  public OnionPerfDownloader(Configuration config) {
    super(config);
    this.mapPathDescriptors.put("recent/torperf", TorperfResult.class);
  }

  /** File containing the download history, which is necessary, because
   * OnionPerf does not delete older .tpf files, but which enables us to do
   * so. */
  private File onionPerfDownloadedFile;

  /** Full URLs of .tpf files downloaded in the current or in past
   * executions. */
  private SortedSet<String> downloadedTpfFiles = new TreeSet<>();

  /** Base URLs of configured OnionPerf hosts. */
  private URL[] onionPerfHosts = null;

  /** Directory for storing archived .tpf files. */
  private File archiveDirectory = null;

  /** Directory for storing recent .tpf files. */
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
    this.readDownloadedOnionPerfTpfFiles();
    this.archiveDirectory = new File(config.getPath(Key.OutputPath).toFile(),
        TORPERF);
    this.recentDirectory = new File(config.getPath(Key.RecentPath).toFile(),
        TORPERF);
    for (URL baseUrl : this.onionPerfHosts) {
      this.downloadFromOnionPerfHost(baseUrl);
    }
    this.writeDownloadedOnionPerfTpfFiles();
    this.cleanUpRsyncDirectory();
  }

  private void readDownloadedOnionPerfTpfFiles() {
    if (!this.onionPerfDownloadedFile.exists()) {
      return;
    }
    try (BufferedReader br = new BufferedReader(new FileReader(
          this.onionPerfDownloadedFile))) {
      String line;
      while ((line = br.readLine()) != null) {
        this.downloadedTpfFiles.add(line);
      }
    } catch (IOException e) {
      logger.info("Unable to read download history file '{}'. Ignoring "
          + "download history and downloading all available .tpf files.",
          this.onionPerfDownloadedFile.getAbsolutePath());
      this.downloadedTpfFiles.clear();
    }
  }

  private void downloadFromOnionPerfHost(URL baseUrl) {
    logger.info("Downloading from OnionPerf host {}", baseUrl);
    List<String> tpfFileNames =
        this.downloadOnionPerfDirectoryListing(baseUrl);
    String source = baseUrl.getHost().split("\\.")[0];
    for (String tpfFileName : tpfFileNames) {
      this.downloadAndParseOnionPerfTpfFile(baseUrl, source, tpfFileName);
    }
  }

  /** Pattern for links contained in directory listings. */
  private static final Pattern TPF_FILE_URL_PATTERN =
      Pattern.compile(".*<a href=\"([^\"]+\\.tpf)\">.*");

  private List<String> downloadOnionPerfDirectoryListing(URL baseUrl) {
    List<String> tpfFileUrls = new ArrayList<>();
    try (BufferedReader br = new BufferedReader(new InputStreamReader(
        baseUrl.openStream()))) {
      String line;
      while ((line = br.readLine()) != null) {
        Matcher matcher = TPF_FILE_URL_PATTERN.matcher(line);
        if (matcher.matches() && !matcher.group(1).startsWith("/")) {
          tpfFileUrls.add(matcher.group(1));
        }
      }
    } catch (IOException e) {
      logger.warn("Unable to download directory listing from '{}'.  Skipping "
          + "this OnionPerf host.", baseUrl);
      tpfFileUrls.clear();
    }
    return tpfFileUrls;
  }

  private static final DateFormat DATE_FORMAT;

  static {
    DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd");
    DATE_FORMAT.setLenient(false);
    DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
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
    if (this.downloadedTpfFiles.contains(tpfFileUrl.toString())) {
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
    File tempFile = new File(this.recentDirectory, "." + tpfFileName);
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
         date.replaceAll("-", "/") + "/" + tpfFileName);
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
    File recentFile = new File(this.recentDirectory, tpfFileName);
    tempFile.renameTo(recentFile);

    /* Add to download history to avoid downloading it again. */
    this.downloadedTpfFiles.add(baseUrl + tpfFileName);
  }

  private void writeDownloadedOnionPerfTpfFiles() {
    this.onionPerfDownloadedFile.getParentFile().mkdirs();
    try (BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.onionPerfDownloadedFile))) {
      for (String line : this.downloadedTpfFiles) {
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

  /** Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() throws ConfigurationException {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<>();
    allFiles.add(new File(config.getPath(Key.RecentPath).toFile(), TORPERF));
    while (!allFiles.isEmpty()) {
      File file = allFiles.pop();
      if (file.isDirectory()) {
        allFiles.addAll(Arrays.asList(file.listFiles()));
      } else if (file.lastModified() < cutOffMillis) {
        file.delete();
      }
    }
  }
}

