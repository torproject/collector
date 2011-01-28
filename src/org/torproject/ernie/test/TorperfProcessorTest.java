/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.test;

import org.torproject.ernie.db.*;

import java.io.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

public class TorperfProcessorTest {

  private File tempTorperfDirectory;
  private File tempStatsDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempTorperfDirectory = folder.newFolder("torperf");
    this.tempStatsDirectory = folder.newFolder("stats");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testTorperfDirectoryNull() {
    new TorperfProcessor(null, this.tempStatsDirectory, null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testStatsDirectoryNull() {
    new TorperfProcessor(this.tempTorperfDirectory, null, null);
  }
}

