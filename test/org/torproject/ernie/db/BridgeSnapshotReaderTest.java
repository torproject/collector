/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.File;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class BridgeSnapshotReaderTest {

  private File tempBridgeDirectoriesDirectory;
  private File tempStatsDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempBridgeDirectoriesDirectory = folder.newFolder("bridges");
    this.tempStatsDirectory = folder.newFolder("stats");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testBridgeDescriptorParserNull() {
    new BridgeSnapshotReader(null, this.tempBridgeDirectoriesDirectory,
        this.tempStatsDirectory);
  }
}

