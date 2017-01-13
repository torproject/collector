/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.cron.Scheduler;

import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;

public class MainTest {

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test()
  public void testInitializationConfigException() throws Exception {
    File tmpFolder = tmpf.newFolder();
    Configuration conf = new Configuration();
    thrown.expect(ConfigurationException.class);
    thrown.expectMessage(Matchers
         .containsString("Cannot watch configuration file."));

    // dir instead of file; the following should throw a ConfigurationException
    conf.setWatchableSourceAndLoad(tmpFolder.toPath());
  }

  private void checkCleanEnv(File conf) {
    assertFalse("Please remove " + Main.CONF_FILE + " before running tests!",
        conf.exists());
  }

  @Test()
  public void testInitializationNullArgs() throws Exception {
    File conf = new File(Main.CONF_FILE);
    checkCleanEnv(conf);
    Main.main(null);
    assertTrue(conf.exists());
    assertTrue(conf.delete());
  }

  @Test()
  public void testInitializationUnwritable() throws Exception {
    File conf = tmpf.newFolder("folder");

    thrown.expect(RuntimeException.class);
    thrown.expectMessage(Matchers
        .allOf(Matchers.containsString("NoSuchFileException"),
             Matchers.containsString("/x/y/z")));

    Main.main(new String[] {
        Paths.get(conf.toString(), "x", "y", "z").toString()});
  }

  @Test()
  public void testInitializationEmptyArgs() throws Exception {
    File conf = new File(Main.CONF_FILE);
    checkCleanEnv(conf);
    Main.main(new String[] { });
    assertTrue(conf.exists());
    assertTrue(conf.delete());
  }

  @Test()
  public void testInitializationTooManyArgs() throws Exception {
    File conf = new File(Main.CONF_FILE);
    checkCleanEnv(conf);
    Main.main(new String[] { "x", "y" });
    assertFalse(conf.exists());
  }

  @Test()
  public void testSmoke() throws Exception {
    File conf = tmpf.newFile("test.conf");
    assertEquals(0L, conf.length());
    Main.main(new String[]{conf.toString()});
    assertTrue(4_000L <= conf.length());
    changeFilePathsAndSetActivation(conf,
        Key.TorperfActivated.name());
    Main.main(new String[]{conf.toString()});
    waitSec(2);
  }

  /** Wait for the given number of seconds. */
  public static void waitSec(int sec) {
    long start = System.currentTimeMillis();
    long toWait = 1_000L * sec;
    do {
      try {
        Thread.sleep(toWait);
      } catch (InterruptedException e) {
        /* Ignore the interruption, but possibly resume sleeping if we didn't
         * sleep long enough. */
      }
    } while ((toWait = start + 1_000L * sec - System.currentTimeMillis()) > 0);
  }

  private void changeFilePathsAndSetActivation(File file, String activation)
      throws Exception {
    List<String> lines = Files.readAllLines(file.toPath(),
        StandardCharsets.UTF_8);
    BufferedWriter bw = Files.newBufferedWriter(file.toPath(),
        StandardCharsets.UTF_8);
    File in = tmpf.newFolder();
    File out = tmpf.newFolder();
    String inStr = "in/";
    String outStr = "out/";
    for (String line : lines) {
      if (line.contains(inStr)) {
        line = line.replace(inStr, in.toString() + inStr);
      } else if (line.contains(outStr)) {
        line = line.replace(outStr, out.toString() + outStr);
      } else if (line.contains(activation)) {
        line = line.replace("false", "true");
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

  /* Verifies that every collecTorMain class is configured in the
   * default collector.properties file and the other way around. */
  @Test()
  public void testRunConfiguration() throws Exception {
    Properties props = new Properties();
    props.load(getClass().getClassLoader().getResourceAsStream(
        Main.CONF_FILE));
    String[] runConfigSettings = new String[] {Scheduler.ACTIVATED,
        Scheduler.PERIODMIN, Scheduler.OFFSETMIN};
    for (Key key : Main.collecTorMains.keySet()) {
      for (String part : runConfigSettings) {
        String key2 = key.name().replace("Activated", part);
        assertNotNull("Property '" + key2 + "' not specified in "
            + Main.CONF_FILE + ".",
            props.getProperty(key2));
      }
    }
    for (String propName : props.stringPropertyNames()) {
      for (String part : runConfigSettings) {
        if (propName.contains(part)) {
          String key2 = propName.replace(part, "");
          assertTrue("CollecTorMain '" + key2
              + "' not specified in Main.class.",
              Main.collecTorMains.containsKey(Key.valueOf(key2 + "Activated")));
        }
      }
    }
  }

  @Test()
  public void testNoModuleActivated() throws Exception {
    Path confPath = tmpf.newFile("test.conf").toPath();
    assertEquals(0L, confPath.toFile().length());

    // create default configuration
    Main.main(new String[]{confPath.toFile().toString()});
    assertTrue(0L < confPath.toFile().length());

    Configuration conf = new Configuration();

    thrown.expect(ConfigurationException.class);
    thrown.expectMessage(Matchers.containsString("Nothing is activated!"));

    // no module activated; the following should throw a ConfigurationException
    conf.setWatchableSourceAndLoad(confPath);
  }
}

