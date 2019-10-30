/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.Key;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Test class for {@link CreateIndexJson}.
 */
public class CreateIndexJsonTest {

  /**
   * Mocked indexer task that does not actually index a file but instead waits
   * for the test class to set index results.
   */
  static class MockedIndexerTask extends IndexerTask {

    /**
     * Index result, to be set by the test.
     */
    private FileNode result;

    /**
     * Create a new mocked indexer task for the given path.
     *
     * @param path Path to index.
     */
    MockedIndexerTask(Path path) {
      super(path);
    }

    /**
     * Set index results.
     *
     * @param result Index results.
     */
    synchronized void setResult(FileNode result) {
      this.result = result;
      this.notifyAll();
    }

    /**
     * Execute the task by waiting for the test to set index results.
     *
     * @return Index results provided by the test.
     */
    @Override
    public FileNode call() {
      synchronized (this) {
        while (null == result) {
          try {
            wait();
          } catch (InterruptedException e) {
            /* Don't care about being interrupted, just keep waiting. */
          }
        }
        return this.result;
      }
    }
  }

  /**
   * List of mocked indexer tasks in the order of creation.
   */
  private List<MockedIndexerTask> indexerTasks = new ArrayList<>();

  /**
   * Testable version of the class under test.
   */
  class TestableCreateIndexJson extends CreateIndexJson {

    /**
     * Create a new instance with the given configuration.
     *
     * @param configuration Configuration for this test.
     */
    TestableCreateIndexJson(Configuration configuration) {
      super(configuration);
    }

    /**
     * Create an indexer task that doesn't actually index a file but that can
     * be controlled by the test, and add that task to the list of tasks.
     *
     * @param fileToIndex File to index.
     * @return Created (mocked) indexer task.
     */
    @Override
    protected IndexerTask createIndexerTask(Path fileToIndex) {
      MockedIndexerTask indexerTask = new MockedIndexerTask(fileToIndex);
      indexerTasks.add(indexerTask);
      return indexerTask;
    }

    /**
     * Return {@code null} as build revision string to make it easier to compare
     * written {@code index.json} files in tests.
     *
     * @return Always {@code null}.
     */
    @Override
    protected String obtainBuildRevision() {
      return null;
    }
  }

  /**
   * Temporary folder containing all files for this test.
   */
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  /**
   * Path to recent exit list file in {@code indexed/recent/}.
   */
  private Path recentExitListFilePath;

  /**
   * Path to archived exit list file in {@code indexed/archive/}.
   */
  private Path archiveExitListFilePath;

  /**
   * Path to exit list link in {@code htdocs/recent/}.
   */
  private Path recentExitListLinkPath;

  /**
   * Path to {@code index.json} file in {@code htdocs/index/}.
   */
  private Path indexJsonPath;

  /**
   * Class under test.
   */
  private CreateIndexJson cij;

  /**
   * Prepares the temporary folder and configuration for this test.
   *
   * @throws IOException Thrown if an I/O error occurs.
   */
  @Before
  public void prepareDirectoriesAndConfiguration() throws IOException {
    Path indexedPath = this.temporaryFolder.newFolder("indexed").toPath();
    this.recentExitListFilePath = indexedPath.resolve(
        Paths.get("recent", "exit-lists", "2016-09-20-13-02-00"));
    this.archiveExitListFilePath = indexedPath.resolve(
        Paths.get("archive", "exit-lists", "exit-list-2016-09.tar.xz"));
    Path htdocsPath = this.temporaryFolder.newFolder("htdocs").toPath();
    this.recentExitListLinkPath = htdocsPath.resolve(
        Paths.get("recent", "exit-lists", "2016-09-20-13-02-00"));
    this.indexJsonPath = htdocsPath.resolve(
        Paths.get("index", "index.json"));
    Configuration configuration = new Configuration();
    configuration.setProperty(Key.IndexedPath.name(),
        indexedPath.toAbsolutePath().toString());
    configuration.setProperty(Key.HtdocsPath.name(),
        htdocsPath.toAbsolutePath().toString());
    configuration.setProperty(Key.InstanceBaseUrl.name(),
        "https://collector.torproject.org");
    this.cij = new TestableCreateIndexJson(configuration);
  }

  /**
   * First execution time.
   */
  private static final Instant firstExecution
      = Instant.parse("2016-09-20T13:04:00Z");

  /**
   * Second execution time, two minutes after the first execution time, which is
   * the default rate for executing this module.
   */
  private static final Instant secondExecution
      = Instant.parse("2016-09-20T13:06:00Z");

  /**
   * Third execution, three hours later than the second execution time, to see
   * if links to files that have been marked for deletion are actually deleted.
   */
  private static final Instant thirdExecution
      = Instant.parse("2016-09-20T16:06:00Z");

  /**
   * Index result from indexing recent exit list.
   */
  private FileNode recentExitListFileNode = FileNode.of(
      "2016-09-20-13-02-00", 177_090L, "2016-09-20 13:02",
      Collections.singletonList("tordnsel 1.0"), "2016-09-20 13:02",
      "2016-09-20 13:02", "4aXdw+jQ5O33AS8n+fUOwD5ZzHCICnwzvxkK8fWDhdw=");

  /**
   * Index result from indexing archived exit list.
   */
  private FileNode archiveExitListFileNode = FileNode.of(
      "exit-list-2016-09.tar.xz", 1_008_748L, "2016-10-04 03:31",
      Collections.singletonList("tordnsel 1.0"), "2016-09-01 00:02",
      "2016-09-30 23:02", "P4zUKVOJFtKzxOXpN3NLU0UBZTBqCAM95yDPJ5JH62g=");

  /**
   * Index result from indexing <i>updated</i> archived exit list.
   */
  private FileNode updatedArchiveExitListFileNode = FileNode.of(
      "exit-list-2016-09.tar.xz", 1_008_748L, "2016-10-07 03:31",
      Collections.singletonList("tordnsel 1.0"), "2016-09-01 00:02",
      "2016-09-30 23:02", "P4zUKVOJFtKzxOXpN3NLU0UBZTBqCAM95yDPJ5JH62g=");

  /**
   * Finish the oldest indexer task by providing the given file node as index
   * result.
   *
   * @param fileNode Index result.
   */
  private void finishIndexing(FileNode fileNode) {
    assertFalse(this.indexerTasks.isEmpty());
    this.indexerTasks.remove(0).setResult(fileNode);
  }

  /**
   * (Almost) empty {@code index.json} file.
   */
  private static final String emptyIndexJsonString
      = "{\"index_created\":\"2016-09-20 13:06\","
      + "\"path\":\"https://collector.torproject.org\"}";

  /**
   * {@code index.json} file containing a single recent exit list.
   */
  private static final String recentExitListIndexJsonString
      = "{\"index_created\":\"2016-09-20 13:06\","
      + "\"path\":\"https://collector.torproject.org\",\"directories\":[{"
      + "\"path\":\"recent\",\"directories\":[{"
      + "\"path\":\"exit-lists\",\"files\":[{"
      + "\"path\":\"2016-09-20-13-02-00\",\"size\":177090,"
      + "\"last_modified\":\"2016-09-20 13:02\","
      + "\"types\":[\"tordnsel 1.0\"],"
      + "\"first_published\":\"2016-09-20 13:02\","
      + "\"last_published\":\"2016-09-20 13:02\","
      + "\"sha256\":\"4aXdw+jQ5O33AS8n+fUOwD5ZzHCICnwzvxkK8fWDhdw=\"}]}]}]}";

  /**
   * {@code index.json} file containing a single archived exit list with a
   * placeholder for the last-modified time.
   */
  private static final String archiveExitListIndexJsonString
      = "{\"index_created\":\"2016-09-20 13:06\","
      + "\"path\":\"https://collector.torproject.org\",\"directories\":[{"
      + "\"path\":\"archive\",\"directories\":[{"
      + "\"path\":\"exit-lists\",\"files\":[{"
      + "\"path\":\"exit-list-2016-09.tar.xz\",\"size\":1008748,"
      + "\"last_modified\":\"%s\","
      + "\"types\":[\"tordnsel 1.0\"],"
      + "\"first_published\":\"2016-09-01 00:02\","
      + "\"last_published\":\"2016-09-30 23:02\","
      + "\"sha256\":\"P4zUKVOJFtKzxOXpN3NLU0UBZTBqCAM95yDPJ5JH62g=\"}]}]}]}";

  /**
   * Delete the given file.
   *
   * @param fileToDelete Path to file to delete.
   */
  private static void deleteFile(Path fileToDelete) {
    try {
      Files.delete(fileToDelete);
    } catch (IOException e) {
      fail(String.format("I/O error while deleting %s.", fileToDelete));
    }
  }

  /**
   * Create the given file.
   *
   * @param fileToCreate Path to file to create.
   * @param lastModified Last-modified time of file to create.
   */
  private static void createFile(Path fileToCreate, Instant lastModified) {
    try {
      Files.createDirectories(fileToCreate.getParent());
      Files.createFile(fileToCreate);
      Files.setLastModifiedTime(fileToCreate, FileTime.from(lastModified));
    } catch (IOException e) {
      fail(String.format("I/O error while creating %s.", fileToCreate));
    }
  }

  /**
   * Return whether the given file exists.
   *
   * @param fileToCheck Path to file to check.
   * @return Whether the file exists.
   */
  private boolean fileExists(Path fileToCheck) {
    return Files.exists(fileToCheck);
  }

  /**
   * Change last-modified time of the given file.
   *
   * @param fileToChange File to change.
   * @param lastModified New last-modified time.
   */
  private void changeLastModified(Path fileToChange, Instant lastModified) {
    try {
      Files.setLastModifiedTime(fileToChange, FileTime.from(lastModified));
    } catch (IOException e) {
      fail(String.format("I/O error while changing last-modified time of %s.",
          fileToChange));
    }
  }

  /**
   * Write the given string to the {@code index.json} file.
   *
   * @param indexJsonString String to write.
   * @param formatArguments Optional format arguments.
   */
  private void writeIndexJson(String indexJsonString,
      Object ... formatArguments) {
    try {
      Files.createDirectories(indexJsonPath.getParent());
      Files.write(indexJsonPath,
          String.format(indexJsonString, formatArguments).getBytes());
    } catch (IOException e) {
      fail("I/O error while writing index.json file.");
    }
  }

  /**
   * Read and return the first line from the {@code index.json} file.
   *
   * @return First line from the {@code index.json} file.
   */
  private String readIndexJson() {
    try {
      return Files.readAllLines(indexJsonPath).get(0);
    } catch (IOException e) {
      fail("I/O error while reading index.json file.");
      return null;
    }
  }

  /**
   * Run the module with the given system time.
   *
   * @param now Time when running the module.
   */
  private void startProcessing(Instant now) {
    this.cij.startProcessing(now);
  }

  /**
   * Test whether two executions on an empty {@code indexed/} directory produce
   * an {@code index.json} file without any files or directories.
   */
  @Test
  public void testEmptyDirs() {
    startProcessing(firstExecution);
    startProcessing(secondExecution);
    assertEquals(emptyIndexJsonString, readIndexJson());
  }

  /**
   * Test whether a new exit list in {@code indexed/recent/} gets indexed and
   * then included in {@code index.json}.
   */
  @Test
  public void testNewRecentExitList() {
    createFile(recentExitListFilePath, Instant.parse("2016-09-20T13:02:00Z"));
    startProcessing(firstExecution);
    finishIndexing(this.recentExitListFileNode);
    startProcessing(secondExecution);
    assertEquals(recentExitListIndexJsonString, readIndexJson());
  }

  /**
   * Test whether an existing exit list in {@code indexed/recent/} that is
   * already contained in {@code index.json} gets ignored by the indexers.
   */
  @Test
  public void testExistingRecentExitList() {
    createFile(recentExitListFilePath, Instant.parse("2016-09-20T13:02:00Z"));
    writeIndexJson(recentExitListIndexJsonString);
    startProcessing(firstExecution);
    startProcessing(secondExecution);
    assertEquals(recentExitListIndexJsonString, readIndexJson());
  }

  /**
   * Test whether a deleted exit list in {@code indexed/recent/} is first
   * removed from {@code index.json} and later deleted from
   * {@code htdocs/recent/}.
   */
  @Test
  public void testDeletedRecentExitList() {
    createFile(recentExitListFilePath, Instant.parse("2016-09-20T13:02:00Z"));
    writeIndexJson(recentExitListIndexJsonString);
    startProcessing(firstExecution);
    assertTrue(fileExists(recentExitListLinkPath));
    deleteFile(recentExitListFilePath);
    startProcessing(secondExecution);
    assertEquals(emptyIndexJsonString, readIndexJson());
    fileExists(recentExitListLinkPath);
    assertTrue(fileExists(recentExitListLinkPath));
    startProcessing(thirdExecution);
    assertFalse(fileExists(recentExitListLinkPath));
  }

  /**
   * Test whether a link in {@code htdocs/recent/} for which no corresponding
   * file in {@code indexed/recent/} exists is eventually deleted.
   */
  @Test
  public void testDeletedLink() {
    createFile(recentExitListLinkPath, Instant.parse("2016-09-20T13:02:00Z"));
    startProcessing(firstExecution);
    assertTrue(Files.exists(recentExitListLinkPath));
    startProcessing(secondExecution);
    assertTrue(Files.exists(recentExitListLinkPath));
    startProcessing(thirdExecution);
    assertFalse(Files.exists(recentExitListLinkPath));
  }

  /**
   * Test whether a tarball that gets deleted while being indexed is not
   * included in {@code index.json} even after indexing is completed.
   */
  @Test
  public void testIndexingDisappearingTarball() {
    createFile(recentExitListFilePath, Instant.parse("2016-09-20T13:02:00Z"));
    startProcessing(firstExecution);
    deleteFile(recentExitListFilePath);
    finishIndexing(recentExitListFileNode);
    startProcessing(secondExecution);
    assertEquals(emptyIndexJsonString, readIndexJson());
  }

  /**
   * Test whether a tarball that gets updated in {@code indexed/archive/} gets
   * re-indexed and updated in {@code index.json}.
   */
  @Test
  public void testUpdatedFile() {
    writeIndexJson(archiveExitListIndexJsonString, "2016-10-04 03:31");
    createFile(archiveExitListFilePath, Instant.parse("2016-10-07T03:31:00Z"));
    startProcessing(firstExecution);
    finishIndexing(updatedArchiveExitListFileNode);
    startProcessing(secondExecution);
    assertEquals(String.format(archiveExitListIndexJsonString,
        "2016-10-07 03:31"), readIndexJson());
  }

  /**
   * Test whether a tarball that gets updated while being indexed is not
   * included in {@code index.json} even after indexing is completed.
   */
  @Test
  public void testUpdateFileWhileIndexing() {
    createFile(archiveExitListFilePath, Instant.parse("2016-10-07T03:31:00Z"));
    startProcessing(firstExecution);
    changeLastModified(archiveExitListFilePath,
        Instant.parse("2016-10-07T03:31:00Z"));
    finishIndexing(archiveExitListFileNode);
    startProcessing(secondExecution);
    assertEquals(String.format(archiveExitListIndexJsonString,
        "2016-10-04 03:31"), readIndexJson());
  }

  /**
   * Test whether a tarball that gets updated after being indexed but before
   * being included in {@code index.json} is not being updated in
   * {@code index.json} until the updated file is being indexed. */
  @Test
  public void testUpdateFileAfterIndexing() {
    createFile(archiveExitListFilePath, Instant.parse("2016-10-04T03:31:00Z"));
    startProcessing(firstExecution);
    finishIndexing(archiveExitListFileNode);
    changeLastModified(archiveExitListFilePath,
        Instant.parse("2016-10-07T03:31:00Z"));
    startProcessing(secondExecution);
    assertEquals(String.format(archiveExitListIndexJsonString,
        "2016-10-04 03:31"), readIndexJson());
  }

  /**
   * Test whether a long-running indexer task is being given the time to finish,
   * rather than starting another task for the same file.
   */
  @Test
  public void testLongRunningIndexerTask() {
    createFile(archiveExitListFilePath, Instant.parse("2016-10-04T03:31:00Z"));
    startProcessing(firstExecution);
    startProcessing(secondExecution);
    assertEquals(emptyIndexJsonString, readIndexJson());
    finishIndexing(archiveExitListFileNode);
    startProcessing(thirdExecution);
    assertTrue(this.indexerTasks.isEmpty());
  }
}

