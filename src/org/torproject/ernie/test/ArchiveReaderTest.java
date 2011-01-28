/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.test;

import org.torproject.ernie.db.*;

import java.io.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

public class ArchiveReaderTest {

  private File tempArchivesDirectory;
  private File tempStatsDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempArchivesDirectory = folder.newFolder("sanitized-bridges");
    this.tempStatsDirectory = folder.newFolder("stats");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testRelayDescriptorParserNull() {
    new ArchiveReader(null, this.tempArchivesDirectory,
        this.tempStatsDirectory, false);
  }
}

