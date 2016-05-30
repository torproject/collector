/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.collector.conf;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.Test;

public class ConfigurationTest {

  private Random randomSource = new Random();

  @Test()
  public void testKeyCount() throws Exception {
    assertEquals("The number of properties keys in enum Key changed."
        + "\n This test class should be adapted.",
        30, Key.values().length);
  }

  @Test()
  public void testConfiguration() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("TorperfOutputDirectory = xyz".getBytes()));
    assertEquals(1, conf.size());
    assertEquals("xyz", conf.getProperty("TorperfOutputDirectory"));
  }

  @Test()
  public void testArrayValues() throws Exception {
    String[] array = new String[randomSource.nextInt(30) + 1];
    for (int i = 0; i < array.length; i++){
      array[i] = Integer.toBinaryString(randomSource.nextInt(100));
    }
    String[] arrays = new String[] {
      Arrays.toString(array).replace("[", "").replace("]", ""),
      Arrays.toString(array).replace("[", "").replace("]", "").replaceAll(" ", "")
    };
    Configuration conf = new Configuration();
    for(String input : arrays) {
      conf.clear();
      conf.load(new ByteArrayInputStream(("CachedRelayDescriptorsDirectories = " + input).getBytes()));
      assertArrayEquals("expected " + Arrays.toString(array) + "\nreceived: "
          + Arrays.toString(conf.getStringArray(Key.CachedRelayDescriptorsDirectories)),
          array, conf.getStringArray(Key.CachedRelayDescriptorsDirectories));
    }
  }

  @Test()
  public void testBoolValues() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream(("CompressRelayDescriptorDownloads=false"
        + "\nImportDirectoryArchives = trUe"
        + "\nReplaceIPAddressesWithHashes= false").getBytes()));
    assertFalse(conf.getBool(Key.CompressRelayDescriptorDownloads));
    assertTrue(conf.getBool(Key.ImportDirectoryArchives));
    assertFalse(conf.getBool(Key.ReplaceIPAddressesWithHashes));
  }

  @Test()
  public void testIntValues() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("BridgeDescriptorMappingsLimit = inf".getBytes()));
    assertEquals(Integer.MAX_VALUE,
        conf.getInt(Key.BridgeDescriptorMappingsLimit));
    int r = randomSource.nextInt(Integer.MAX_VALUE);
    conf.clear();
    conf.load(new ByteArrayInputStream(("BridgeDescriptorMappingsLimit =" + r).getBytes()));
    assertEquals(r,
        conf.getInt(Key.BridgeDescriptorMappingsLimit));
   }

  @Test()
  public void testFileValues() throws Exception {
    String[] files = new String[] { "/the/path/file.txt", "another/path"};
    Configuration conf = new Configuration();
    for(String file : files) {
      conf.clear();
      conf.load(new ByteArrayInputStream(("DirectoryArchivesOutputDirectory = " + file).getBytes()));
      assertEquals(new File(file), conf.getPath(Key.DirectoryArchivesOutputDirectory).toFile());
    }
  }

  @Test()
  public void testArrayArrayValues() throws Exception {
    String[][] sourceStrings = new String[][] {
      new String[]{"localsource", "http://127.0.0.1:12345"},
      new String[]{"somesource", "https://some.host.org:12345"}};
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream(("TorperfSources = "
        + Arrays.deepToString(sourceStrings)).replace("[[", "").replace("]]", "")
            .replace("], [", Configuration.ARRAYSEP).getBytes()));
    assertArrayEquals(sourceStrings, conf.getStringArrayArray(Key.TorperfSources));
  }

  @Test( expected = ConfigurationException.class)
  public void testArrayArrayValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("CachedRelayDescriptorsDirectories".getBytes()));
    conf.getStringArrayArray(Key.TorperfOutputDirectory);
  }

  @Test( expected = ConfigurationException.class)
  public void testArrayValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("CachedRelayDescriptorsDirectories".getBytes()));
    conf.getStringArray(Key.TorperfSources);
  }

  @Test( expected = ConfigurationException.class)
  public void testBoolValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("TorperfSource = http://x.y.z".getBytes()));
    conf.getBool(Key.CachedRelayDescriptorsDirectories);
  }

  @Test( expected = ConfigurationException.class)
  public void testPathValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("DirectoryArchivesDirectory = \\u0000:".getBytes()));
    conf.getPath(Key.DirectoryArchivesDirectory);
  }

  @Test( expected = ConfigurationException.class)
  public void testIntValueException() throws Exception {
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream("BridgeDescriptorMappingsLimit = y7".getBytes()));
    conf.getInt(Key.BridgeDescriptorMappingsLimit);
  }

}
