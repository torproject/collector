/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import org.torproject.ernie.db.*;

import java.io.*;
import java.util.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

public class CachedRelayDescriptorReaderTest {

  private File tempStatsDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempStatsDirectory = folder.newFolder("stats");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testRelayDescriptorParserNull() {
    new CachedRelayDescriptorReader(null, new ArrayList<String>(),
        this.tempStatsDirectory);
  }
}

