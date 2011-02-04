/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.test;

import org.torproject.ernie.db.*;

import java.io.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

public class SanitizedBridgesWriterTest {

  private File tempSanitizedBridgesDirectory;
  private File tempStatsDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempSanitizedBridgesDirectory =
        folder.newFolder("sanitized-bridges");
    this.tempStatsDirectory = folder.newFolder("stats");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSanitizedBridgesDirectoryNull() {
    new SanitizedBridgesWriter(null, this.tempStatsDirectory, false, -1L);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testStatsDirectoryNull() {
    new SanitizedBridgesWriter(this.tempSanitizedBridgesDirectory, null,
        false, -1L);
  }
}

