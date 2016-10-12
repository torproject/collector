/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.conf;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.torproject.collector.Main;
import org.torproject.collector.MainTest;
import org.torproject.collector.cron.CollecTorMain;
import org.torproject.collector.cron.Dummy;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Observable;
import java.util.Observer;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

public class ConfigurationTest {

  private Random randomSource = new Random();

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test()
  public void testKeyCount() throws Exception {
    assertEquals("The number of properties keys in enum Key changed."
        + "\n This test class should be adapted.",
        46, Key.values().length);
  }

  @Test()
  public void testConfiguration() throws Exception {
    Configuration conf = new Configuration();
    String val = "xyz";
    conf.setProperty(Key.OutputPath.name(), val);
    assertEquals(1, conf.size());
    assertEquals(val, conf.getProperty(Key.OutputPath.name()));
  }

  private String propLine(Key key, String val) {
    return key.name() + " = " + val + "\n";
  }

  @Test()
  public void testArrayValues() throws Exception {
    String[] array = new String[randomSource.nextInt(30) + 1];
    for (int i = 0; i < array.length; i++) {
      array[i] = Integer.toBinaryString(randomSource.nextInt(100));
    }
    String[] arrays = new String[] {
      Arrays.toString(array).replace("[", "").replace("]", ""),
      Arrays.toString(array).replace("[", "").replace("]", "")
          .replaceAll(" ", "")
    };
    Configuration conf = new Configuration();
    for (String input : arrays) {
      conf.clear();
      conf.setProperty(Key.CachedRelayDescriptorsDirectories.name(), input);
      assertArrayEquals("expected " + Arrays.toString(array) + "\nreceived: "
          + Arrays.toString(conf
              .getStringArray(Key.CachedRelayDescriptorsDirectories)),
          array, conf.getStringArray(Key.CachedRelayDescriptorsDirectories));
    }
  }

  @Test()
  public void testBoolValues() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.CompressRelayDescriptorDownloads.name(), "false");
    conf.setProperty(Key.ImportDirectoryArchives.name(), "trUe");
    conf.setProperty(Key.ReplaceIpAddressesWithHashes.name(), "false");
    assertFalse(conf.getBool(Key.CompressRelayDescriptorDownloads));
    assertTrue(conf.getBool(Key.ImportDirectoryArchives));
    assertFalse(conf.getBool(Key.ReplaceIpAddressesWithHashes));
  }

  @Test()
  public void testIntValues() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.BridgeDescriptorMappingsLimit.name(), "inf");
    assertEquals(Integer.MAX_VALUE,
        conf.getInt(Key.BridgeDescriptorMappingsLimit));
    int randomInt = randomSource.nextInt(Integer.MAX_VALUE);
    conf.clear();
    conf.load(new ByteArrayInputStream(
        propLine(Key.BridgeDescriptorMappingsLimit,
        "" + randomInt).getBytes()));
    assertEquals(randomInt,
        conf.getInt(Key.BridgeDescriptorMappingsLimit));
  }

  @Test()
  public void testFileValues() throws Exception {
    String[] files = new String[] { "/the/path/file.txt", "another/path"};
    Configuration conf = new Configuration();
    for (String file : files) {
      conf.clear();
      conf.setProperty(Key.OutputPath.name(), file);
      assertEquals(new File(file),
          conf.getPath(Key.OutputPath).toFile());
    }
  }

  @Test()
  public void testArrayArrayValues() throws Exception {
    String[][] sourceStrings = new String[][] {
      new String[]{"localsource", "http://127.0.0.1:12345"},
      new String[]{"somesource", "https://some.host.org:12345"}};
    Configuration conf = new Configuration();
    conf.setProperty(Key.TorperfSources.name(),
        Arrays.deepToString(sourceStrings).replace("[[", "").replace("]]", "")
            .replace("], [", Configuration.ARRAYSEP));
    assertArrayEquals(sourceStrings,
        conf.getStringArrayArray(Key.TorperfSources));
  }

  @Test(expected = ConfigurationException.class)
  public void testArrayArrayValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.CachedRelayDescriptorsDirectories.name(), "");
    conf.getStringArrayArray(Key.OutputPath);
  }

  @Test(expected = ConfigurationException.class)
  public void testArrayValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.CachedRelayDescriptorsDirectories.name(), "");
    conf.getStringArray(Key.TorperfSources);
  }

  @Test(expected = ConfigurationException.class)
  public void testBoolValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.TorperfSources.name(), "http://x.y.z");
    conf.getBool(Key.CachedRelayDescriptorsDirectories);
  }

  @Test(expected = ConfigurationException.class)
  public void testPathValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.DirectoryArchivesDirectory.name(), "\\\u0000:");
    conf.getPath(Key.DirectoryArchivesDirectory);
  }

  @Test(expected = ConfigurationException.class)
  public void testUrlValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.ExitlistUrl.name(), "xxx://y.y.y");
    conf.getUrl(Key.ExitlistUrl);
  }

  @Test(expected = ConfigurationException.class)
  public void testIntValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.setProperty(Key.BridgeDescriptorMappingsLimit.name(), "y7");
    conf.getInt(Key.BridgeDescriptorMappingsLimit);
  }

  @Test(expected = ConfigurationException.class)
  public void testSetWatchableSourceAndLoad() throws Exception {
    Configuration conf = new Configuration();
    conf.setWatchableSourceAndLoad(Paths.get("/tmp/phantom.path"));
  }

  @Test()
  public void testConfigChange() throws Exception {
    Configuration conf = new Configuration();
    final AtomicBoolean called = new AtomicBoolean(false);
    conf.addObserver(new Observer() {
        public void update(Observable obs, Object obj) {
          called.set(true);
        }
      });
    File confFile = tmpf.newFile("empty");
    Files.write(confFile.toPath(), (Key.RelaydescsActivated.name() + "=true")
        .getBytes());
    conf.setWatchableSourceAndLoad(confFile.toPath());
    MainTest.waitSec(1);
    confFile.setLastModified(System.currentTimeMillis());
    MainTest.waitSec(6);
    assertTrue("Update was not called.", called.get());
    called.set(false);
    MainTest.waitSec(6);
    assertFalse("Update was called.", called.get());
  }

  @Test()
  public void testConfigUnreadable() throws Exception {
    Configuration conf = new Configuration();
    final AtomicBoolean called = new AtomicBoolean(false);
    conf.addObserver(new Observer() {
        public void update(Observable obs, Object obj) {
          called.set(true);
        }
      });
    File confFile = tmpf.newFile("empty");
    Files.write(confFile.toPath(), (Key.RelaydescsActivated.name() + "=true")
        .getBytes());
    conf.setWatchableSourceAndLoad(confFile.toPath());
    MainTest.waitSec(1);
    confFile.delete();
    conf.setProperty(Key.ImportDirectoryArchives.name(), "false");
    final Dummy dummy = new Dummy(conf);
    tmpf.newFolder("empty");
    MainTest.waitSec(6);
    assertFalse("Update was called.", called.get());
    assertEquals(0, conf.size());
    Field confField = CollecTorMain.class.getDeclaredField("config");
    confField.setAccessible(true);
    int size = ((Configuration)(confField.get(dummy))).size();
    assertEquals(2, size);
  }

}
