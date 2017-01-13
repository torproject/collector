/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.index;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.cron.CollecTorMain;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.zip.GZIPOutputStream;

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

  /** Creates indexes of directories containing archived and recent
   * descriptors and write index files to disk. */
  public CreateIndexJson(Configuration conf) {
    super(conf);
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
  protected void startProcessing() throws ConfigurationException {
    try {
      indexJsonFile = new File(config.getPath(Key.IndexPath).toFile(),
          "index.json");
      basePath = config.getProperty(Key.InstanceBaseUrl.name());
      indexedDirectories = new File[] {
          config.getPath(Key.ArchivePath).toFile(),
          config.getPath(Key.RecentPath).toFile() };
      writeIndex(indexDirectories());
    } catch (Exception e) {
      logger.error("Cannot run index creation: " + e.getMessage(), e);
      throw new RuntimeException(e);
    }
  }

  private class DirectoryNode implements Comparable<DirectoryNode> {
    String path;
    SortedSet<FileNode> files;
    SortedSet<DirectoryNode> directories;

    DirectoryNode(String path, SortedSet<FileNode> files,
        SortedSet<DirectoryNode> directories) {
      this.path = path;
      this.files = files;
      this.directories = directories;
    }

    public int compareTo(DirectoryNode other) {
      return this.path.compareTo(other.path);
    }
  }

  @SuppressWarnings({"checkstyle:membername", "checkstyle:parametername"})
  private class IndexNode {
    String index_created;
    String path;
    SortedSet<FileNode> files;
    SortedSet<DirectoryNode> directories;

    IndexNode(String index_created, String path,
        SortedSet<FileNode> files,
        SortedSet<DirectoryNode> directories) {
      this.index_created = index_created;
      this.path = path;
      this.files = files;
      this.directories = directories;
    }
  }

  @SuppressWarnings({"checkstyle:membername", "checkstyle:parametername"})
  private class FileNode implements Comparable<FileNode> {
    String path;
    long size;
    String last_modified;

    FileNode(String path, long size, String last_modified) {
      this.path = path;
      this.size = size;
      this.last_modified = last_modified;
    }

    public int compareTo(FileNode other) {
      return this.path.compareTo(other.path);
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
    SortedSet<DirectoryNode> directoryNodes =
        new TreeSet<DirectoryNode>();
    logger.trace("indexing: " + indexedDirectories[0] + " "
        + indexedDirectories[1]);
    for (File directory : indexedDirectories) {
      if (directory.exists() && directory.isDirectory()) {
        DirectoryNode dn = indexDirectory(directory);
        if (null != dn) {
          directoryNodes.add(dn);
        }
      }
    }
    return new IndexNode(dateTimeFormat.format(
        System.currentTimeMillis()), basePath, null, directoryNodes);
  }

  private DirectoryNode indexDirectory(File directory) {
    SortedSet<FileNode> fileNodes = new TreeSet<FileNode>();
    SortedSet<DirectoryNode> directoryNodes =
        new TreeSet<DirectoryNode>();
    logger.trace("indexing: " + directory);
    File[] fileList = directory.listFiles();
    if (null == fileList) {
      logger.warn("Indexing dubious directory: " + directory);
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
    DirectoryNode directoryNode = new DirectoryNode(
        directory.getName(), fileNodes.isEmpty() ? null : fileNodes,
        directoryNodes.isEmpty() ? null : directoryNodes);
    return directoryNode;
  }

  private FileNode indexFile(File file) {
    FileNode fileNode = new FileNode(file.getName(), file.length(),
        dateTimeFormat.format(file.lastModified()));
    return fileNode;
  }

  private void writeIndex(IndexNode indexNode) throws IOException {
    indexJsonFile.getParentFile().mkdirs();
    Gson gson = new GsonBuilder().create();
    String indexNodeString = gson.toJson(indexNode);
    Writer[] writers = new Writer[] {
        new FileWriter(indexJsonFile),
        new OutputStreamWriter(new GZIPOutputStream(
            new FileOutputStream(indexJsonFile + ".gz"))),
        new OutputStreamWriter(new XZCompressorOutputStream(
            new FileOutputStream(indexJsonFile + ".xz"))),
        new OutputStreamWriter(new BZip2CompressorOutputStream(
            new FileOutputStream(indexJsonFile + ".bz2")))
    };
    for (Writer writer : writers) {
      BufferedWriter bufferedWriter = new BufferedWriter(writer);
      bufferedWriter.write(indexNodeString);
      bufferedWriter.close();
    }
  }
}

