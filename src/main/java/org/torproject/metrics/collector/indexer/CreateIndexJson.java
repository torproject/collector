/* Copyright 2015--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.cron.CollecTorMain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAmount;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Create an index file called {@code index.json} containing metadata of all
 * files in the {@code indexed/} directory and update the {@code htdocs/}
 * directory to contain all files to be served via the web server.
 *
 * <p>File metadata includes:</p>
 * <ul>
 *   <li>Path for downloading this file from the web server.</li>
 *   <li>Size of the file in bytes.</li>
 *   <li>Timestamp when the file was last modified.</li>
 *   <li>Descriptor types as found in {@code @type} annotations of contained
 *   descriptors.</li>
 *   <li>Earliest and latest publication timestamp of contained
 *   descriptors.</li>
 *   <li>SHA-256 digest of the file.</li>
 * </ul>
 *
 * <p>This class maintains its own working directory {@code htdocs/} with
 * subdirectories like {@code htdocs/archive/} or {@code htdocs/recent/} and
 * another subdirectory {@code htdocs/index/}. The first two subdirectories
 * contain (hard) links created and deleted by this class, the third
 * subdirectory contains the {@code index.json} file in uncompressed and
 * compressed forms.</p>
 *
 * <p>The main reason for having the {@code htdocs/} directory is that indexing
 * a large descriptor file can be time consuming. New or updated files in
 * {@code indexed/} first need to be indexed before their metadata can be
 * included in {@code index.json}. Another reason is that files removed from
 * {@code indexed/} shall still be available for download for a limited period
 * of time after disappearing from {@code index.json}.</p>
 *
 * <p>The reason for creating (hard) links in {@code htdocs/}, rather than
 * copies, is that links do not consume additional disk space. All directories
 * must be located on the same file system. Storing symbolic links in
 * {@code htdocs/} would not have worked with replaced or deleted files in the
 * original directories. Symbolic links in original directories are allowed as
 * long as they target to the same file system.</p>
 *
 * <p>This class does not write, modify, or delete any files in the
 * {@code indexed/} directory. At the same time it does not expect any other
 * classes to write, modify, or delete contents in the {@code htdocs/}
 * directory.</p>
 */
public class CreateIndexJson extends CollecTorMain {

  /**
   * Class logger.
   */
  private static final Logger logger =
      LoggerFactory.getLogger(CreateIndexJson.class);

  /**
   * Delay between finding out that a file has been deleted and deleting its
   * link.
   */
  private static final TemporalAmount deletionDelay = Duration.ofHours(2L);

  /**
   * Index tarballs with no more than this many threads at a time.
   */
  private static final int tarballIndexerThreads = 3;

  /**
   * Index flat files with no more than this many threads at a time.
   */
  private static final int flatFileIndexerThreads = 3;

  /**
   * Parser and formatter for all timestamps found in {@code index.json}.
   */
  private static DateTimeFormatter dateTimeFormatter = DateTimeFormatter
      .ofPattern("uuuu-MM-dd HH:mm").withZone(ZoneOffset.UTC);

  /**
   * Object mapper for parsing and formatting {@code index.json} files.
   */
  private static ObjectMapper objectMapper = new ObjectMapper()
      .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE)
      .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
      .setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE)
      .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

  /**
   * Path to the {@code indexed/} directory.
   */
  private Path indexedPath;

  /**
   * Path to the {@code htdocs/} directory.
   */
  private Path htdocsPath;

  /**
   * Path to the uncompressed {@code index.json} file.
   */
  private Path indexJsonPath;

  /**
   * Base URL of all resources included in {@code index.json}.
   */
  private String basePathString;

  /**
   * Git revision of this software to be included in {@code index.json} or
   * omitted if unknown.
   */
  private String buildRevisionString;

  /**
   * Index containing metadata of files in {@code indexed/}, including new or
   * updated files that still need to be indexed and deleted files that are
   * still linked in {@code htdocs/}.
   *
   * <p>This map is initialized by reading the last known {@code index.json}
   * file and remains available in memory between executions until shutdown.</p>
   */
  private SortedMap<Path, FileNode> index;

  /**
   * Executor for indexing tarballs.
   */
  private ExecutorService tarballsExecutor
      = Executors.newFixedThreadPool(tarballIndexerThreads);

  /**
   * Executor for indexing flat files (non-tarballs).
   */
  private ExecutorService flatFilesExecutor
      = Executors.newFixedThreadPool(flatFileIndexerThreads);

  /**
   * Initialize this class with the given {@code configuration}.
   *
   * @param configuration Configuration values.
   */
  public CreateIndexJson(Configuration configuration) {
    super(configuration);
  }

  @Override
  public String module() {
    return "updateindex";
  }

  @Override
  protected String syncMarker() {
    return "IndexJson";
  }


  /**
   * Run the indexer by (1) adding new files from {@code indexed/} to the index,
   * (2) adding old files from {@code htdocs/} for which only links exist to the
   * index, (3) scheduling new tasks and updating links in {@code htdocs/} to
   * reflect what's contained in the in-memory index, and (4) writing new
   * uncompressed and compressed {@code index.json} files to disk.
   */
  @Override
  public void startProcessing() {
    this.startProcessing(Instant.now());
  }

  /**
   * Helper method to {@link #startProcessing()} that accepts the current
   * execution time and which is used by tests.
   *
   * @param now Current execution time.
   */
  protected void startProcessing(Instant now) {
    try {
      this.basePathString = this.config.getProperty(Key.InstanceBaseUrl.name());
      this.indexedPath = config.getPath(Key.IndexedPath);
      this.htdocsPath = config.getPath(Key.HtdocsPath);
    } catch (ConfigurationException e) {
      logger.error("Unable to read one or more configuration values. Not "
          + "indexing in this execution.", e);
    }
    this.buildRevisionString = this.obtainBuildRevision();
    this.indexJsonPath = this.htdocsPath
        .resolve(Paths.get("index", "index.json"));
    try {
      this.prepareHtdocsDirectory();
      if (null == this.index) {
        logger.info("Reading index.json file from last execution.");
        this.index = this.readIndex();
      }
      logger.info("Going through indexed/ and adding new files to the index.");
      this.addNewFilesToIndex(this.indexedPath);
      logger.info("Going through htdocs/ and adding links to deleted files to "
          + "the index.");
      this.addOldLinksToIndex();
      logger.info("Going through the index, scheduling tasks, and updating "
          + "links.");
      this.scheduleTasksAndUpdateLinks(now);
      logger.info("Writing uncompressed and compressed index.json files to "
          + "disk.");
      this.writeIndex(this.index, now);
      Runtime rt = Runtime.getRuntime();
      logger.info("Current memory usage is: free = {} B, total = {} B, "
          + "max = {} B.",
          rt.freeMemory(), rt.totalMemory(), rt.maxMemory());
      logger.info("Pausing until next index update run.");
    } catch (IOException e) {
      logger.error("I/O error while updating index.json files. Trying again in "
          + "the next execution.", e);
    }
  }

  /**
   * Prepare the {@code htdocs/} directory by checking whether all required
   * subdirectories exist and by creating them if not.
   *
   * @throws IOException Thrown if one or more directories could not be created.
   */
  private void prepareHtdocsDirectory() throws IOException {
    for (Path requiredPath : new Path[] {
        this.htdocsPath,
        this.indexJsonPath.getParent() }) {
      if (!Files.exists(requiredPath)) {
        Files.createDirectories(requiredPath);
      }
    }
  }

  /**
   * Read the {@code index.json} file written by the previous execution and
   * populate our index with its contents, or leave the index empty if this is
   * the first execution and that file does not yet exist.
   *
   * @return Index read from disk, or empty map if {@code index.json} does not
   *     exist.
   */
  private SortedMap<Path, FileNode> readIndex() throws IOException {
    SortedMap<Path, FileNode> index = new TreeMap<>();
    if (Files.exists(this.indexJsonPath)) {
      IndexNode indexNode = objectMapper.readValue(
          Files.newInputStream(this.indexJsonPath), IndexNode.class);
      SortedMap<Path, DirectoryNode> directoryNodes = new TreeMap<>();
      directoryNodes.put(Paths.get(""), indexNode);
      while (!directoryNodes.isEmpty()) {
        Path directoryPath = directoryNodes.firstKey();
        DirectoryNode directoryNode = directoryNodes.remove(directoryPath);
        if (null != directoryNode.files) {
          for (FileNode fileNode : directoryNode.files) {
            Path filePath = this.indexedPath.resolve(directoryPath)
                .resolve(Paths.get(fileNode.path));
            index.put(filePath, fileNode);
          }
        }
        if (null != directoryNode.directories) {
          boolean isRootDirectory = directoryNode == indexNode;
          for (DirectoryNode subdirectoryNode : directoryNode.directories) {
            Path subdirectoryPath = isRootDirectory
                ? Paths.get(subdirectoryNode.path)
                : directoryPath.resolve(Paths.get(subdirectoryNode.path));
            directoryNodes.put(subdirectoryPath, subdirectoryNode);
          }
        }
      }
    }
    return index;
  }

  /**
   * Obtain and return the build revision string that was generated during the
   * build process with {@code git rev-parse --short HEAD} and written to
   * {@code collector.buildrevision.properties}, or return {@code null} if the
   * build revision string cannot be obtained.
   *
   * @return Build revision string.
   */
  protected String obtainBuildRevision() {
    String buildRevision = null;
    Properties buildProperties = new Properties();
    String propertiesFile = "collector.buildrevision.properties";
    try (InputStream is = getClass().getClassLoader()
        .getResourceAsStream(propertiesFile)) {
      if (null == is) {
        logger.warn("File {}, which is supposed to contain the build revision "
            + "string, does not exist in our class path. Writing index.json "
            + "without the \"build_revision\" field.", propertiesFile);
        return null;
      }
      buildProperties.load(is);
      buildRevision = buildProperties.getProperty(
          "collector.build.revision", null);
    } catch (IOException e) {
      logger.warn("I/O error while trying to obtain build revision string. "
          + "Writing index.json without the \"build_revision\" field.");
    }
    return buildRevision;
  }

  /**
   * Walk the given file tree and add all previously unknown files to the
   * in-memory index (except for files starting with "." or ending with ".tmp").
   *
   * @param path File tree to walk.
   */
  private void addNewFilesToIndex(Path path) throws IOException {
    if (!Files.exists(path)) {
      return;
    }
    Files.walkFileTree(path, new SimpleFileVisitor<Path>() {
      @Override
      public FileVisitResult visitFile(Path filePath,
          BasicFileAttributes basicFileAttributes) {
        if (!filePath.toString().startsWith(".")
            && !filePath.toString().endsWith(".tmp")) {
          index.putIfAbsent(filePath, new FileNode());
        }
        return FileVisitResult.CONTINUE;
      }
    });
  }

  /**
   * Walk the file tree of the {@code htdocs/} directory and add all previously
   * unknown links to the in-memory index to ensure their deletion when they're
   * known to be deleted from their original directories.
   */
  private void addOldLinksToIndex() throws IOException {
    Path htdocsIndexPath = this.indexJsonPath.getParent();
    Files.walkFileTree(this.htdocsPath, new SimpleFileVisitor<Path>() {
      @Override
      public FileVisitResult visitFile(Path linkPath,
          BasicFileAttributes basicFileAttributes) {
        if (!linkPath.startsWith(htdocsIndexPath)) {
          Path filePath = indexedPath.resolve(htdocsPath.relativize(linkPath));
          index.putIfAbsent(filePath, new FileNode());
        }
        return FileVisitResult.CONTINUE;
      }
    });
  }

  /**
   * Go through the index, schedule tasks to index files, and update links.
   *
   * @throws IOException Thrown if an I/O exception occurs while creating or
   *     deleting links.
   */
  private void scheduleTasksAndUpdateLinks(Instant now) throws IOException {
    int queuedIndexerTasks = 0;
    Map<Path, FileNode> indexingResults = new HashMap<>();
    SortedSet<Path> filesToIndex = new TreeSet<>();
    Map<Path, Path> linksToCreate = new HashMap<>();
    Set<FileNode> linksToMarkForDeletion = new HashSet<>();
    Map<Path, Path> linksToDelete = new HashMap<>();
    for (Map.Entry<Path, FileNode> e : this.index.entrySet()) {
      Path filePath = e.getKey();
      Path linkPath = this.htdocsPath
          .resolve(this.indexedPath.relativize(filePath));
      FileNode fileNode = e.getValue();
      if (Files.exists(filePath)) {
        if (null != fileNode.indexerResult) {
          if (!fileNode.indexerResult.isDone()) {
            /* This file is currently being indexed, so we should just skip it
             * and wait until the indexer is done. */
            queuedIndexerTasks++;
            continue;
          }
          try {
            /* Indexing is done, obtain index results. */
            fileNode = fileNode.indexerResult.get();
            indexingResults.put(filePath, fileNode);
          } catch (InterruptedException | ExecutionException ex) {
            /* Clear index result, so that we can give this file another try
             * next time. */
            fileNode.indexerResult = null;
          }
        }
        String originalLastModified = dateTimeFormatter
            .format(Files.getLastModifiedTime(filePath).toInstant());
        if (!originalLastModified.equals(fileNode.lastModified)) {
          /* We either don't have any index results for this file, or we only
           * have index results for an older version of this file. */
          filesToIndex.add(filePath);
        } else if (!Files.exists(linkPath)) {
          /* We do have index results, but we don't have a link yet, so we're
           * going to create a link. */
          linksToCreate.put(linkPath, filePath);
          if (null != fileNode.markedForDeletion) {
            /* We had already marked the link for deletion, but given that the
             * original file has returned, we're going to list this file again
             * and not delete the link in the future. */
            fileNode.markedForDeletion = null;
          }
        } else {
          String linkLastModified = dateTimeFormatter
              .format(Files.getLastModifiedTime(linkPath).toInstant());
          if (!linkLastModified.equals(fileNode.lastModified)) {
            /* We do have index results plus a link to an older version of this
             * file, so we'll have to update the link. */
            linksToCreate.put(linkPath, filePath);
          }
        }
      } else {
        if (null == fileNode.markedForDeletion) {
          /* We're noticing just now that the file doesn't exist anymore, so
           * we're going to mark it for deletion but not deleting the link right
           * away. */
          linksToMarkForDeletion.add(fileNode);
        } else if (fileNode.markedForDeletion
            .isBefore(now.minus(deletionDelay))) {
          /* The file doesn't exist anymore, and we found out long enough ago,
           * so we can now go ahead and delete the link. */
          linksToDelete.put(linkPath, filePath);
        }
      }
    }
    if (queuedIndexerTasks > 0) {
      logger.info("Counting {} file(s) being currently indexed or in the "
          + "queue.", queuedIndexerTasks);
    }
    this.updateIndex(indexingResults);
    this.scheduleTasks(filesToIndex);
    this.createLinks(linksToCreate);
    this.markForDeletion(linksToMarkForDeletion, now);
    this.deleteLinks(linksToDelete);
  }

  /**
   * Update index with index results.
   */
  private void updateIndex(Map<Path, FileNode> indexResults) {
    if (!indexResults.isEmpty()) {
      logger.info("Updating {} index entries with index results.",
          indexResults.size());
      this.index.putAll(indexResults);
    }
  }

  /**
   * Schedule indexing the given set of descriptor files, using different queues
   * for tarballs and flat files.
   *
   * @param filesToIndex Paths to descriptor files to index.
   */
  private void scheduleTasks(SortedSet<Path> filesToIndex) {
    if (!filesToIndex.isEmpty()) {
      logger.info("Scheduling {} indexer task(s).", filesToIndex.size());
      for (Path fileToIndex : filesToIndex) {
        IndexerTask indexerTask = this.createIndexerTask(fileToIndex);
        if (fileToIndex.getFileName().toString().endsWith(".tar.xz")) {
          this.index.get(fileToIndex).indexerResult
              = this.tarballsExecutor.submit(indexerTask);
        } else {
          this.index.get(fileToIndex).indexerResult
              = this.flatFilesExecutor.submit(indexerTask);
        }
      }
    }
  }

  /**
   * Create an indexer task for indexing the given file.
   *
   * <p>The reason why this is a separate method is that it can be overriden by
   * tests that don't actually want to index files but instead provide their own
   * index results.</p>
   *
   * @param fileToIndex File to index.
   * @return Indexer task.
   */
  protected IndexerTask createIndexerTask(Path fileToIndex) {
    return new IndexerTask(fileToIndex);
  }

  /**
   * Create links in {@code htdocs/}, including all necessary parent
   * directories.
   *
   * @param linksToCreate Map of links to be created with keys being link paths
   *     and values being original file paths.
   * @throws IOException Thrown if an I/O error occurs.
   */
  private void createLinks(Map<Path, Path> linksToCreate) throws IOException {
    if (!linksToCreate.isEmpty()) {
      logger.info("Creating {} new link(s).", linksToCreate.size());
      for (Map.Entry<Path, Path> e : linksToCreate.entrySet()) {
        Path linkPath = e.getKey();
        Path originalPath = e.getValue();
        Files.createDirectories(linkPath.getParent());
        Files.deleteIfExists(linkPath);
        Files.createLink(linkPath, originalPath);
      }
    }
  }

  /**
   * Mark the given links for deletion in the in-memory index.
   *
   * @param linksToMarkForDeletion Files to be marked for deletion.
   */
  private void markForDeletion(Set<FileNode> linksToMarkForDeletion,
      Instant now) {
    if (!linksToMarkForDeletion.isEmpty()) {
      logger.info("Marking {} old link(s) for deletion.",
          linksToMarkForDeletion.size());
      for (FileNode fileNode : linksToMarkForDeletion) {
        fileNode.markedForDeletion = now;
      }
    }
  }

  /**
   * Delete the given links from {@code htdocs/}.
   *
   * @param linksToDelete Map of links to be deleted with keys being link paths
   *     and values being original file paths.
   * @throws IOException Thrown if an I/O error occurs.
   */
  private void deleteLinks(Map<Path, Path> linksToDelete) throws IOException {
    if (!linksToDelete.isEmpty()) {
      logger.info("Deleting {} old link(s).", linksToDelete.size());
      for (Map.Entry<Path, Path> e : linksToDelete.entrySet()) {
        Path linkPath = e.getKey();
        Path originalPath = e.getValue();
        Files.deleteIfExists(linkPath);
        index.remove(originalPath);
      }
    }
  }

  /**
   * Write the in-memory index to {@code index.json} and its compressed
   * variants, but exclude files that have not yet been indexed or that are
   * marked for deletion.
   *
   * @throws IOException Thrown if an I/O error occurs while writing files.
   */
  private void writeIndex(SortedMap<Path, FileNode> index,
      Instant now) throws IOException {
    IndexNode indexNode = new IndexNode();
    indexNode.indexCreated = dateTimeFormatter.format(now);
    indexNode.buildRevision = this.buildRevisionString;
    indexNode.path = this.basePathString;
    SortedMap<Path, DirectoryNode> directoryNodes = new TreeMap<>();
    for (Map.Entry<Path, FileNode> indexEntry : index.entrySet()) {
      Path filePath = this.indexedPath.relativize(indexEntry.getKey());
      FileNode fileNode = indexEntry.getValue();
      if (null == fileNode.lastModified || null != fileNode.markedForDeletion) {
        /* Skip unindexed or deleted files. */
        continue;
      }
      Path directoryPath = null;
      DirectoryNode parentDirectoryNode = indexNode;
      if (null != filePath.getParent()) {
        for (Path pathPart : filePath.getParent()) {
          directoryPath = null == directoryPath ? pathPart
              : directoryPath.resolve(pathPart);
          DirectoryNode directoryNode = directoryNodes.get(directoryPath);
          if (null == directoryNode) {
            directoryNode = new DirectoryNode();
            directoryNode.path = pathPart.toString();
            if (null == parentDirectoryNode.directories) {
              parentDirectoryNode.directories = new ArrayList<>();
            }
            parentDirectoryNode.directories.add(directoryNode);
            directoryNodes.put(directoryPath, directoryNode);
          }
          parentDirectoryNode = directoryNode;
        }
      }
      if (null == parentDirectoryNode.files) {
        parentDirectoryNode.files = new ArrayList<>();
      }
      parentDirectoryNode.files.add(fileNode);
    }
    Path htdocsIndexPath = this.indexJsonPath.getParent();
    try (OutputStream uncompressed
            = Files.newOutputStream(htdocsIndexPath.resolve(".index.json.tmp"));
        OutputStream bz2Compressed = new BZip2CompressorOutputStream(
            Files.newOutputStream(htdocsIndexPath.resolve("index.json.bz2")));
        OutputStream gzCompressed = new GzipCompressorOutputStream(
            Files.newOutputStream(htdocsIndexPath.resolve("index.json.gz")));
        OutputStream xzCompressed = new XZCompressorOutputStream(
            Files.newOutputStream(htdocsIndexPath.resolve("index.json.xz")))) {
      objectMapper.writeValue(uncompressed, indexNode);
      objectMapper.writeValue(bz2Compressed, indexNode);
      objectMapper.writeValue(gzCompressed, indexNode);
      objectMapper.writeValue(xzCompressed, indexNode);
    }
    Files.move(htdocsIndexPath.resolve(".index.json.tmp"), this.indexJsonPath,
        StandardCopyOption.REPLACE_EXISTING);
  }
}

