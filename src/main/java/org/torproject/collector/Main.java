/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector;

import org.torproject.collector.bridgedescs.SanitizedBridgesWriter;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.exitlists.ExitListDownloader;
import org.torproject.collector.index.CreateIndexJson;
import org.torproject.collector.relaydescs.ArchiveWriter;
import org.torproject.collector.torperf.TorperfDownloader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;

/**
 * Main class for starting a CollecTor instance.
 * <br>
 * Run without arguments in order to read the usage information, i.e.
 * <br>
 * <code>java -jar collector.jar</code>
 */
public class Main {

  private static Logger log = LoggerFactory.getLogger(Main.class);
  public static final String CONF_FILE = "collector.properties";

  /** All possible main classes.
   * If a new CollecTorMain class is available, just add it to this map.
   */
  static final Map<String, Class> collecTorMains = new HashMap<>();

  static { // add a new main class here
    collecTorMains.put("bridgedescs", SanitizedBridgesWriter.class);
    collecTorMains.put("exitlists", ExitListDownloader.class);
    collecTorMains.put("updateindex", CreateIndexJson.class);
    collecTorMains.put("relaydescs", ArchiveWriter.class);
    collecTorMains.put("torperf", TorperfDownloader.class);
  }

  private static final String modules = collecTorMains.keySet().toString()
      .replace("[", "").replace("]", "").replaceAll(", ", "|");

  private static Configuration conf = new Configuration();

  /**
   * One argument is necessary.
   * See class description {@link Main}.
   */
  public static void main(String[] args) throws Exception {
    File confFile = null;
    if (null == args || args.length < 1 || args.length > 2) {
      printUsage("CollecTor needs one or two arguments.");
      return;
    } else if (args.length == 1) {
      confFile = new File(CONF_FILE);
    } else if (args.length == 2) {
      confFile = new File(args[1]);
    }
    if (!confFile.exists() || confFile.length() < 1L) {
      writeDefaultConfig(confFile);
      return;
    } else {
      readConfigurationFrom(confFile);
    }
    invokeGivenMain(args[0]);
  }

  private static void printUsage(String msg) {
    final String usage = "Usage:\njava -jar collector.jar "
        + "<" + modules + ">  [path/to/configFile]";
    System.out.println(msg + "\n" + usage);
  }

  private static void writeDefaultConfig(File confFile) {
    try {
      Files.copy(Main.class.getClassLoader().getResource(CONF_FILE).openStream(),
          confFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
      printUsage("Could not find config file. In the default "
          + "configuration, we are not configured to read data from any "
          + "data source or write data to any data sink. You need to "
          + "change the configuration (" + CONF_FILE
          + ") and provide at least one data source and one data sink. "
          + "Refer to the manual for more information.");
    } catch (IOException e) {
      log.error("Cannot write default configuration. Reason: " + e, e);
    }
  }

  private static void readConfigurationFrom(File confFile) throws Exception {
    try (FileInputStream fis = new FileInputStream(confFile)) {
      conf.load(fis);
    } catch (Exception e) { // catch all possible problems
      log.error("Cannot read configuration. Reason: " + e, e);
      throw e;
    }
  }

  private static void invokeGivenMain(String mainId) {
    Class clazz = collecTorMains.get(mainId);
    if (null == clazz) {
      printUsage("Unknown argument: " + mainId);
    }
    invokeMainOnClass(clazz);
  }

  private static void invokeMainOnClass(Class clazz) {
    try {
      clazz.getMethod("main", new Class[] { Configuration.class })
          .invoke(null, (Object) conf);
    } catch (NoSuchMethodException | IllegalAccessException
       | InvocationTargetException e) {
      log.error("Cannot invoke 'main' method on "
          + clazz.getName() + ". " + e, e);
    }
  }
}

