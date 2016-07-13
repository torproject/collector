/* Copyright 2015--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.index;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;

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
public class CreateIndexJson {

  private static File indexJsonFile;

  private static String basePath = "https://collector.torproject.org";

  private static File[] indexedDirectories;

  static final String dateTimePattern = "yyyy-MM-dd HH:mm";

  static final Locale dateTimeLocale = Locale.US;

  static final TimeZone dateTimezone = TimeZone.getTimeZone("UTC");

  @SuppressWarnings("checkstyle:javadocmethod")
  public static void main(Configuration config)
      throws ConfigurationException, IOException {
    indexJsonFile =  new File(config.getPath(Key.IndexPath).toFile(), "index.json");
    indexedDirectories = new File[] {
        new File(config.getPath(Key.ArchivePath).toFile(), "archive"),
        new File(config.getPath(Key.RecentPath).toFile(), "recent") };
    writeIndex(indexDirectories());
  }

  static class DirectoryNode implements Comparable<DirectoryNode> {
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
  static class IndexNode {
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
  static class FileNode implements Comparable<FileNode> {
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

  static DateFormat dateTimeFormat;

  static {
    dateTimeFormat = new SimpleDateFormat(dateTimePattern,
        dateTimeLocale);
    dateTimeFormat.setLenient(false);
    dateTimeFormat.setTimeZone(dateTimezone);
  }

  static IndexNode indexDirectories() {
    SortedSet<DirectoryNode> directoryNodes =
        new TreeSet<DirectoryNode>();
    for (File directory : indexedDirectories) {
      if (directory.exists() && directory.isDirectory()) {
        directoryNodes.add(indexDirectory(directory));
      }
    }
    return new IndexNode(dateTimeFormat.format(
        System.currentTimeMillis()), basePath, null, directoryNodes);
  }

  static DirectoryNode indexDirectory(File directory) {
    SortedSet<FileNode> fileNodes = new TreeSet<FileNode>();
    SortedSet<DirectoryNode> directoryNodes =
        new TreeSet<DirectoryNode>();
    for (File fileOrDirectory : directory.listFiles()) {
      if (fileOrDirectory.getName().startsWith(".")) {
        continue;
      }
      if (fileOrDirectory.isFile()) {
        fileNodes.add(indexFile(fileOrDirectory));
      } else {
        directoryNodes.add(indexDirectory(fileOrDirectory));
      }
    }
    DirectoryNode directoryNode = new DirectoryNode(
        directory.getName(), fileNodes.isEmpty() ? null : fileNodes,
        directoryNodes.isEmpty() ? null : directoryNodes);
    return directoryNode;
  }

  static FileNode indexFile(File file) {
    FileNode fileNode = new FileNode(file.getName(), file.length(),
        dateTimeFormat.format(file.lastModified()));
    return fileNode;
  }

  static void writeIndex(IndexNode indexNode) throws IOException {
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

