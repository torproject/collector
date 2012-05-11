/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class ArchiveWriterTest {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Test(expected = IllegalArgumentException.class)
  public void testArchivesDirectoryNull() {
    new ArchiveWriter(null);
  }
}

