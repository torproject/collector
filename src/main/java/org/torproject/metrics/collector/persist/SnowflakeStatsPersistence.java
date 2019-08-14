/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.SnowflakeStats;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class SnowflakeStatsPersistence
    extends DescriptorPersistence<SnowflakeStats> {

  private static final String SNOWFLAKES = "snowflakes";

  public SnowflakeStatsPersistence(SnowflakeStats desc) {
    super(desc, Annotation.SnowflakeStats.bytes());
    calculatePaths();
  }

  private void calculatePaths() {
    DateTimeFormatter directoriesFormatter = DateTimeFormatter
        .ofPattern("uuuu/MM/dd").withZone(ZoneOffset.UTC);
    String[] directories = this.desc.snowflakeStatsEnd()
        .format(directoriesFormatter).split("/");
    DateTimeFormatter fileFormatter = DateTimeFormatter
        .ofPattern("uuuu-MM-dd-HH-mm-ss").withZone(ZoneOffset.UTC);
    String fileOut = this.desc.snowflakeStatsEnd().format(fileFormatter)
        + "-snowflake-stats";
    this.recentPath = Paths.get(SNOWFLAKES, fileOut).toString();
    this.storagePath = Paths.get(SNOWFLAKES, directories[0], directories[1],
        directories[2], fileOut).toString();
  }
}

