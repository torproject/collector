/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.collector.cron;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.collector.conf.Key;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.cron.Scheduler;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

public class CollecTorMainTest {

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test()
  public void testCheckAvailableSpace() {
    File someFile = null;
    try {
      someFile = tmpf.newFile("existing.file");
      assertTrue(someFile.exists());
    } catch (IOException ioe) {
      fail("Cannot perform test. File creation failed.");
    }
    CollecTorMain.checkAvailableSpace(someFile.toPath());
    CollecTorMain.checkAvailableSpace(Paths.get("/fantasy", "path", "non",
        "existant", "but", "no", "exception"));
  }

}

