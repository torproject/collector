/* Copyright 2015--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import org.torproject.descriptor.index.DirectoryNode;
import org.torproject.descriptor.index.FileNode;
import org.torproject.descriptor.index.IndexNode;
import org.torproject.descriptor.internal.FileType;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.Properties;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;

/* Create a fresh index.json containing all directories and files in the
 * archive/ and recent/ directories.
 *
 * Note that if this ever takes longer than a few seconds, we'll have to
 * cache index parts of directories or files that haven't changed.
 * Example: if we parse include cryptographic hashes or @type information,
 * we'll likely have to do that. */
public class CreateIndexJson extends CollecTorMain {

  private static final Logger logger =
      LoggerFactory.getLogger(CreateIndexJson.class);

  private static File indexJsonFile;

  private static String basePath;

  private static File[] indexedDirectories;

  private static final String dateTimePattern = "yyyy-MM-dd HH:mm";

  private static final Locale dateTimeLocale = Locale.US;

  private static final TimeZone dateTimezone = TimeZone.getTimeZone("UTC");

  private static String buildRevision = null;

  /** Creates indexes of directories containing archived and recent
   * descriptors and write index files to disk. */
  public CreateIndexJson(Configuration conf) {
    super(conf);
    Properties buildProperties = new Properties();
    try (InputStream is = getClass().getClassLoader()
        .getResourceAsStream("collector.buildrevision.properties")) {
      buildProperties.load(is);
      buildRevision = buildProperties.getProperty("collector.build.revision",
          null);
    } catch (Exception ex) {
      // This doesn't hamper the index creation: only log a warning.
      logger.warn("No build revision available.", ex);
      buildRevision = null;
    }
  }

  @Override
  public String module() {
    return "updateindex";
  }

  @Override
  protected String syncMarker() {
    return "IndexJson";
  }

  @Override
  protected void startProcessing() {
    try {
      indexJsonFile = new File(config.getPath(Key.IndexPath).toFile(),
          "index.json");
      basePath = config.getProperty(Key.InstanceBaseUrl.name());
      indexedDirectories = new File[] {
          config.getPath(Key.ArchivePath).toFile(),
          config.getPath(Key.ContribPath).toFile(),
          config.getPath(Key.RecentPath).toFile() };
      writeIndex(indexDirectories());
    } catch (Exception e) {
      logger.error("Cannot run index creation: {}", e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  private static DateFormat dateTimeFormat;

  static {
    dateTimeFormat = new SimpleDateFormat(dateTimePattern,
        dateTimeLocale);
    dateTimeFormat.setLenient(false);
    dateTimeFormat.setTimeZone(dateTimezone);
  }

  private IndexNode indexDirectories() {
    SortedSet<DirectoryNode> directoryNodes = new TreeSet<>();
    logger.trace("indexing: {} {}", indexedDirectories[0],
        indexedDirectories[1]);
    for (File directory : indexedDirectories) {
      if (directory.exists() && directory.isDirectory()) {
        DirectoryNode dn = indexDirectory(directory);
        if (null != dn) {
          directoryNodes.add(dn);
        }
      }
    }
    return new IndexNode(dateTimeFormat.format(
        System.currentTimeMillis()), buildRevision, basePath, null,
        directoryNodes);
  }

  private DirectoryNode indexDirectory(File directory) {
    SortedSet<FileNode> fileNodes = new TreeSet<>();
    SortedSet<DirectoryNode> directoryNodes = new TreeSet<>();
    logger.trace("indexing: {}", directory);
    File[] fileList = directory.listFiles();
    if (null == fileList) {
      logger.warn("Indexing dubious directory: {}", directory);
      return null;
    }
    for (File fileOrDirectory : fileList) {
      if (fileOrDirectory.getName().startsWith(".")
          || fileOrDirectory.getName().endsWith(".tmp")) {
        continue;
      }
      if (fileOrDirectory.isFile()) {
        fileNodes.add(indexFile(fileOrDirectory));
      } else {
        DirectoryNode dn = indexDirectory(fileOrDirectory);
        if (null != dn) {
          directoryNodes.add(dn);
        }
      }
    }
    return new DirectoryNode(
        directory.getName(), fileNodes.isEmpty() ? null : fileNodes,
        directoryNodes.isEmpty() ? null : directoryNodes);
  }

  private FileNode indexFile(File file) {
    return new FileNode(file.getName(), file.length(),
        dateTimeFormat.format(file.lastModified()));
  }

  private void writeIndex(IndexNode indexNode) throws Exception {
    indexJsonFile.getParentFile().mkdirs();
    String indexNodeString = IndexNode.makeJsonString(indexNode);
    for (String filename : new String[] {indexJsonFile.toString(),
        indexJsonFile + ".gz", indexJsonFile + ".xz", indexJsonFile + ".bz2"}) {
      FileType type = FileType.valueOf(
          filename.substring(filename.lastIndexOf(".") + 1).toUpperCase());
      try (BufferedWriter bufferedWriter
          = new BufferedWriter(new OutputStreamWriter(type.outputStream(
          new FileOutputStream(filename))))) {
        bufferedWriter.write(indexNodeString);
      }
    }
  }

}

