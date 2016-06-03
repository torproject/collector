/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.conf;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

/**
 * Initialize configuration with defaults from collector.properties,
 * unless a configuration properties file is available.
 */
public class Configuration extends Properties {

  public static final String FIELDSEP = ",";
  public static final String ARRAYSEP = ";";

  /**
   * Returns {@code String[][]} from a property. Commas seperate array elements
   * and semicolons separate arrays, e.g.,
   * {@code propertyname = a1, a2, a3; b1, b2, b3}
   */
  public String[][] getStringArrayArray(Key key) throws ConfigurationException {
    try {
      checkClass(key, String[][].class);
      String[] interim = getProperty(key.name()).split(ARRAYSEP);
      String[][] res = new String[interim.length][];
      for (int i = 0; i < interim.length; i++) {
        res[i] = interim[i].trim().split(FIELDSEP);
        for (int j = 0; j < res[i].length; j++) {
          res[i][j] = res[i][j].trim();
        }
      }
      return res;
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  /**
   * Returns {@code String[]} from a property. Commas seperate array elements,
   * e.g.,
   * {@code propertyname = a1, a2, a3}
   */
  public String[] getStringArray(Key key) throws ConfigurationException {
    try {
      checkClass(key, String[].class);
      String[] res = getProperty(key.name()).split(FIELDSEP);
      for (int i = 0; i < res.length; i++) {
        res[i] = res[i].trim();
      }
      return res;
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  private void checkClass(Key key, Class clazz) {
    if (!key.keyClass().getSimpleName().equals(clazz.getSimpleName())) {
      throw new RuntimeException("Wrong type wanted! My class is "
          + key.keyClass().getSimpleName());
    }
  }

  /**
   * Returns a {@code boolean} property (case insensitiv), e.g.
   * {@code propertyOne = True}.
   */
  public boolean getBool(Key key) throws ConfigurationException {
    try {
      checkClass(key, Boolean.class);
      return Boolean.parseBoolean(getProperty(key.name()));
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  /**
   * Parse an integer property and translate the String
   * <code>"inf"</code> into Integer.MAX_VALUE.
   * Verifies that this enum is a Key for an integer value.
   */
  public int getInt(Key key) throws ConfigurationException {
    try {
      checkClass(key, Integer.class);
      String prop = getProperty(key.name());
      if ("inf".equals(prop)) {
        return Integer.MAX_VALUE;
      } else {
        return Integer.parseInt(prop);
      }
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  /**
   * Returns a {@code Path} property, e.g.
   * {@code pathProperty = /my/path/file}.
   */
  public Path getPath(Key key) throws ConfigurationException {
    try {
      checkClass(key, Path.class);
      return Paths.get(getProperty(key.name()));
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

}
