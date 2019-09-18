/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BridgedbMetrics;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class BridgedbMetricsPersistence
    extends DescriptorPersistence<BridgedbMetrics> {

  private static final String BRIDGEDB_STATS = "bridgedb-metrics";

  public BridgedbMetricsPersistence(BridgedbMetrics desc) {
    super(desc, Annotation.BridgedbMetrics.bytes());
    calculatePaths();
  }

  private void calculatePaths() {
    DateTimeFormatter directoriesFormatter = DateTimeFormatter
        .ofPattern("uuuu/MM/dd").withZone(ZoneOffset.UTC);
    String[] directories = this.desc.bridgedbMetricsEnd()
        .format(directoriesFormatter).split("/");
    DateTimeFormatter fileFormatter = DateTimeFormatter
        .ofPattern("uuuu-MM-dd-HH-mm-ss").withZone(ZoneOffset.UTC);
    String fileOut = this.desc.bridgedbMetricsEnd().format(fileFormatter)
        + "-bridgedb-metrics";
    this.recentPath = Paths.get(BRIDGEDB_STATS, fileOut).toString();
    this.storagePath = Paths.get(BRIDGEDB_STATS, directories[0], directories[1],
        directories[2], fileOut).toString();
  }
}

