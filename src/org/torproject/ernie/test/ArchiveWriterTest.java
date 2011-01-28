/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.test;

import org.torproject.ernie.db.*;

import java.io.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

public class ArchiveWriterTest {

  private File tempArchivesDirectory;

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Before
  public void createTempDirectories() {
    this.tempArchivesDirectory = folder.newFolder("archives");
  }

  @Test(expected = IllegalArgumentException.class)
  public void testArchivesDirectoryNull() {
    new ArchiveWriter(null);
  }
}

