/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.webstats;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class SanitizeWeblogsTest {

  @Test
  public void bytesForTest() {
    String lines = "line\nline\nline\nline\nline\n"
        + "line\nline\nline\nline\nline\n";
    assertEquals(lines, new String(SanitizeWeblogs.bytesFor("line", 10)));
  }

}

