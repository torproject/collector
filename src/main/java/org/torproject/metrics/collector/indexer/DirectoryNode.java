/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import java.util.List;

/**
 * Directory node in {@code index.json} which is discarded after reading and
 * re-created before writing that file.
 */
@JsonPropertyOrder({ "path", "files", "directories" })
class DirectoryNode {

  /**
   * Relative path of the directory.
   */
  @JsonProperty("path")
  String path;

  /**
   * List of file objects of files available from this directory.
   */
  @JsonProperty("files")
  List<FileNode> files;

  /**
   * List of directory objects of directories available from this directory.
   */
  @JsonProperty("directories")
  List<DirectoryNode> directories;
}

