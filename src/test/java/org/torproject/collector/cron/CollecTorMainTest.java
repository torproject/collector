/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.collector.Main;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.Key;
import org.torproject.collector.sync.SyncManager;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

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

  /* Verifies that every sync-marker is configured in the
   * default collector.properties file and the other way around. */
  @Test()
  public void testSyncMarker() throws Exception {
    Properties props = new Properties();
    props.load(getClass().getClassLoader().getResourceAsStream(
        Main.CONF_FILE));
    String[] syncSettings = new String[] {CollecTorMain.SOURCES,
        SyncManager.SYNCORIGINS};
    Field ctmField = Main.class.getDeclaredField("collecTorMains");
    ctmField.setAccessible(true);
    Map<Key, Class<? extends CollecTorMain>> ctms
        = (Map<Key, Class<? extends CollecTorMain>>) ctmField.get(Main.class);
    List<String> markers = new ArrayList<>();
    for (Map.Entry<Key, Class<? extends CollecTorMain>> entry
        : ctms.entrySet()) {
      String marker = entry.getValue().getConstructor(Configuration.class)
          .newInstance(new Configuration()).syncMarker();
      markers.add(marker);
      String key = marker + CollecTorMain.SOURCES;
      String sources = props.getProperty(key);
      switch (marker) {
        case "Relay":
        case "Bridge":
        case "Exitlist":
          assertNotNull("Property '" + key
              + "' not specified in " + Main.CONF_FILE + ".",
              props.getProperty(key));
          break;
        default:
          assertNull("Property '"  + key
              + "' should not be listed in " + Main.CONF_FILE + ".",
              props.getProperty(key));
          break;
      }
    }
    for (String propName : props.stringPropertyNames()) {
      for (String part : syncSettings) {
        if (propName.endsWith(part)) {
          String key = propName.replace(part, "");
          assertTrue("CollecTorMain '" + key + "' not specified in Main.class.",
              markers.contains(key));
        }
      }
    }
  }

}

