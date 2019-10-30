/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Root node in {@code index.json} containing additional information about index
 * creation time or Git revision used for creating it.
 */
@JsonPropertyOrder({ "index_created", "build_revision", "path", "files",
    "directories" })
class IndexNode extends DirectoryNode {

  /**
   * Timestamp when this index was created using pattern
   * {@code "YYYY-MM-DD HH:MM"} in the UTC timezone.
   */
  @JsonProperty("index_created")
  String indexCreated;

  /**
   * Git revision of this software.
   */
  @JsonProperty("build_revision")
  String buildRevision;
}

