/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.time.Instant;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.Future;

/**
 * File node in {@code index.json}, also used for storing volatile metadata
 * like whether a descriptor file is currently being indexed or whether its
 * link in {@code htdocs/} is marked for deletion.
 */
@JsonPropertyOrder({ "path", "size", "last_modified", "types",
    "first_published", "last_published", "sha256" })
class FileNode {

  /**
   * Relative path of the file.
   */
  @JsonProperty("path")
  String path;

  /**
   * Size of the file in bytes.
   */
  @JsonProperty("size")
  Long size;

  /**
   * Timestamp when the file was last modified using pattern
   * {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   */
  @JsonProperty("last_modified")
  String lastModified;

  /**
   * Descriptor types as found in {@code @type} annotations of contained
   * descriptors.
   */
  @JsonProperty("types")
  SortedSet<String> types;

  /**
   * Earliest publication timestamp of contained descriptors using pattern
   * {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   */
  @JsonProperty("first_published")
  String firstPublished;

  /**
   * Latest publication timestamp of contained descriptors using pattern
   * {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   */
  @JsonProperty("last_published")
  String lastPublished;

  /**
   * SHA-256 digest of this file.
   */
  @JsonProperty("sha256")
  String sha256;

  /**
   * Indexer result that will be available as soon as the indexer has completed
   * its task.
   */
  @JsonIgnore
  Future<FileNode> indexerResult;

  /**
   * Timestamp when this file was first not found anymore in {@code indexed/},
   * used to keep the link in {@code htdocs/} around for another 2 hours before
   * deleting it, too.
   *
   * <p>This field is ignored when writing {@code index.json}, because it's an
   * internal detail that nobody else cares about. The effect is that links
   * might be around for longer than 2 hours in case of a restart, which seems
   * acceptable.</p>
   */
  @JsonIgnore
  Instant markedForDeletion;

  /**
   * Create and return a {@link FileNode} instance with the given values.
   *
   * @param path Relative path of the file.
   * @param size Size of the file in bytes.
   * @param lastModified Timestamp when the file was last modified using pattern
   *     {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   * @param types Descriptor types as found in {@code @type} annotations of
   *     contained descriptors.
   * @param firstPublished Earliest publication timestamp of contained
   *     descriptors using pattern {@code "YYYY-MM-DD HH:MM"} in the UTC
   *     timezone.
   * @param lastPublished Latest publication timestamp of contained descriptors
   *     using pattern {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   * @param sha256 SHA-256 digest of this file.
   *
   * @return {@link FileNode} instance with the given values.
   */
  static FileNode of(String path, Long size, String lastModified,
      Iterable<String> types, String firstPublished, String lastPublished,
      String sha256) {
    FileNode fileNode = new FileNode();
    fileNode.path = path;
    fileNode.size = size;
    fileNode.lastModified = lastModified;
    fileNode.types = new TreeSet<>();
    for (String type : types) {
      fileNode.types.add(type);
    }
    fileNode.firstPublished = firstPublished;
    fileNode.lastPublished = lastPublished;
    fileNode.sha256 = sha256;
    return fileNode;
  }
}

