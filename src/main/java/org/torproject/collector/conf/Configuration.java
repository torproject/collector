/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.conf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.util.EnumSet;
import java.util.Observable;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Initialize configuration with defaults from collector.properties,
 * unless a configuration properties file is available.
 */
public class Configuration extends Observable implements Cloneable {

  private static final Logger logger = LoggerFactory.getLogger(
      Configuration.class);

  private final ScheduledExecutorService scheduler =
      Executors.newScheduledThreadPool(1);

  public static final String FIELDSEP = ",";
  public static final String ARRAYSEP = ";";

  private final Properties props = new Properties();
  private Path configurationFile;
  private FileTime ft;

  /**
   * Load the configuration from the given path and start monitoring changes.
   * If the file was changed, re-read and inform all observers.
   */
  public void setWatchableSourceAndLoad(final Path confPath) throws
      ConfigurationException {
    this.configurationFile = confPath;
    try {
      ft = Files.getLastModifiedTime(confPath);
      reload();
      anythingActivated();
    } catch (IOException e) {
      throw new ConfigurationException("Cannot watch configuration file. "
          + "Reason: " + e.getMessage(), e);
    }
    if (this.getBool(Key.RunOnce)) { // no need to watch
      return;
    }
    this.scheduler.scheduleAtFixedRate(new Runnable() {
        public void run() {
          logger.trace("Check configuration file.");
            try {
              FileTime ftNow = Files.getLastModifiedTime(confPath);
              if (ft.compareTo(ftNow) < 0) {
                logger.info("Configuration file was changed.");
                reload();
                setChanged();
                notifyObservers(null);
              }
              ft = ftNow;
            } catch (Throwable th) { // Catch all and keep running.
              logger.error("Cannot reload configuration file.", th);
            }
        }
      }, 5, 5, TimeUnit.SECONDS);
  }

  private final void reload() throws IOException {
    props.clear();
    try (FileInputStream fis
        = new FileInputStream(configurationFile.toFile())) {
      props.load(fis);
    }
  }

  private void anythingActivated() throws ConfigurationException {
    if (!(this.getBool(Key.RelaydescsActivated)
        || this.getBool(Key.BridgedescsActivated)
        || this.getBool(Key.ExitlistsActivated)
        || this.getBool(Key.UpdateindexActivated)
        || this.getBool(Key.TorperfActivated))) {
      throw new ConfigurationException("Nothing is activated!\n"
          + "Please edit collector.properties. Exiting.");
    }
  }

  /** Return a copy of all properties. */
  public Properties getPropertiesCopy() {
    return (Properties) props.clone();
  }

  /**
   * Loads properties from the given stream.
   */
  public void load(InputStream fis) throws IOException {
    props.load(fis);
  }

  /** Retrieves the value for key. */
  public String getProperty(String key) {
    return props.getProperty(key);
  }

  /** Retrieves the value for key returning a default for non-existing keys. */
  public String getProperty(String key, String def) {
    return props.getProperty(key, def);
  }

  /** Sets the value for key. */
  public void setProperty(String key, String value) {
    props.setProperty(key, value);
  }

  /** clears all properties. */
  public void clear() {
    props.clear();
  }

  /** Add all given properties. */
  public void putAll(Properties allProps) {
    props.putAll(allProps);
  }

  /** Count of properties. */
  public int size() {
    return props.size();
  }

  /**
   * Returns {@code String[][]} from a property. Commas seperate array elements
   * and semicolons separate arrays, e.g.,
   * {@code propertyname = a1, a2, a3; b1, b2, b3}
   */
  public String[][] getStringArrayArray(Key key) throws ConfigurationException {
    try {
      checkClass(key, String[][].class);
      String[] interim = props.getProperty(key.name()).split(ARRAYSEP);
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
      String[] res = props.getProperty(key.name()).split(FIELDSEP);
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
      return Boolean.parseBoolean(props.getProperty(key.name()));
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
      String prop = props.getProperty(key.name());
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
   * Parse a long property.
   * Verifies that this enum is a Key for a Long value.
   */
  public long getLong(Key key) throws ConfigurationException {
    try {
      checkClass(key, Long.class);
      String prop = props.getProperty(key.name());
      return Long.parseLong(prop);
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
      return Paths.get(props.getProperty(key.name()));
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  /**
   * Returns a {@code SourceType} as List, e.g.
   * {@code sourcetypeproperty = Remote, Sync}.
   */
  public Set<SourceType> getSourceTypeSet(Key key)
      throws ConfigurationException {
    Set<SourceType> res = null;
    try {
      checkClass(key, SourceType[].class);
      String[] interim = props.getProperty(key.name()).split(FIELDSEP);
      for (int i = 0; i < interim.length; i++) {
        SourceType st = SourceType.valueOf(interim[i].trim());
        if (null == res) {
          res = EnumSet.of(st);
        } else {
          res.add(st);
        }
      }
      return res;
    } catch (RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

  /**
   * Returns a {@code URL} property, e.g.
   * {@code urlProperty = https://my.url.here}.
   */
  public URL getUrl(Key key) throws ConfigurationException {
    try {
      checkClass(key, URL.class);
      return new URL(props.getProperty(key.name()));
    } catch (MalformedURLException | RuntimeException mue) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + mue.getMessage(), mue);
    }
  }

  /**
   * Returns {@code URL[]} from a property. Commas seperate array elements,
   * e.g.,
   * {@code propertyname = a1.example.org, a2.example2.com, a3.example3.net}
   */
  public URL[] getUrlArray(Key key) throws ConfigurationException {
    try {
      checkClass(key, URL[].class);
      String[] interim = props.getProperty(key.name()).split(FIELDSEP);
      URL[] res = new URL[interim.length];
      for (int i = 0; i < interim.length; i++) {
        res[i] = new URL(interim[i].trim());
      }
      return res;
    } catch (MalformedURLException | RuntimeException re) {
      throw new ConfigurationException("Corrupt property: " + key
          + " reason: " + re.getMessage(), re);
    }
  }

}
