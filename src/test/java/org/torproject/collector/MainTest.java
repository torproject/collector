/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.collector;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import org.torproject.collector.conf.Key;
import org.torproject.collector.conf.ConfigurationException;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URL;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.AccessControlException;
import java.security.Policy;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Random;

import org.junit.rules.TemporaryFolder;
import org.junit.Rule;
import org.junit.Test;

public class MainTest {

  private Random randomSource = new Random();

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test()
  public void testSmoke() throws Exception {
    System.out.println("\n!!!!   Three ERROR log messages are expected."
        + "\nOne each from: ExitListDownloader, "
        + "TorperfDownloader, and CreateIndexJson.\n");
    File conf = tmpf.newFile("test.conf");
    File lockPath = tmpf.newFolder("test.lock");
    assertEquals(0L, conf.length());
    Main.main(new String[]{"relaydescs", conf.toString()});
    assertTrue(4_000L <= conf.length());
    changeLockFilePath(conf, lockPath);
    for ( String key : Main.collecTorMains.keySet()) {
      Main.main(new String[]{key, conf.toString()});
    }
  }

  private void changeLockFilePath(File f, File l) throws Exception {
    List<String> lines = Files.readAllLines(f.toPath());
    BufferedWriter bw = Files.newBufferedWriter(f.toPath());
    File out = tmpf.newFolder();
    for(String line : lines) {
      if (line.contains(Key.LockFilePath.name())) {
        line = Key.LockFilePath.name() + " = " + l.toString();
      } else if (line.contains("out")) {
        line = line.replace("out", out.toString() + "out");
      }
      bw.write(line);
      bw.newLine();
    }
    bw.flush();
    bw.close();
  }

  /* Verifies the contents of the default collector.properties file.
   * All properties specified have to be present but nothing else. */
  @Test()
  public void testPropertiesFile() throws Exception {
    Properties props = new Properties();
    props.load(getClass().getClassLoader().getResourceAsStream(
        Main.CONF_FILE));
    for (Key key : Key.values()) {
      assertNotNull("Property '" + key.name() + "' not specified in "
          + Main.CONF_FILE + ".",
          props.getProperty(key.name()));
    }
    for (String propName : props.stringPropertyNames()) {
      try {
        Key.valueOf(propName);
      } catch (IllegalArgumentException ex) {
        fail("Invalid property name '" + propName + "' found in "
            + Main.CONF_FILE + ".");
      }
    }
  }
}

