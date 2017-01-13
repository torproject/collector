/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector;

import org.torproject.collector.bridgedescs.SanitizedBridgesWriter;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.cron.CollecTorMain;
import org.torproject.collector.cron.Scheduler;
import org.torproject.collector.cron.ShutdownHook;
import org.torproject.collector.exitlists.ExitListDownloader;
import org.torproject.collector.index.CreateIndexJson;
import org.torproject.collector.relaydescs.ArchiveWriter;
import org.torproject.collector.torperf.TorperfDownloader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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

  private static final Logger log = LoggerFactory.getLogger(Main.class);

  public static final String CONF_FILE = "collector.properties";

  /** All possible main classes.
   * If a new CollecTorMain class is available, just add it to this map.
   */
  static final Map<Key, Class<? extends CollecTorMain>> collecTorMains =
      new HashMap<>();

  static { // add a new main class here
    collecTorMains.put(Key.BridgedescsActivated, SanitizedBridgesWriter.class);
    collecTorMains.put(Key.ExitlistsActivated, ExitListDownloader.class);
    collecTorMains.put(Key.UpdateindexActivated, CreateIndexJson.class);
    collecTorMains.put(Key.RelaydescsActivated, ArchiveWriter.class);
    collecTorMains.put(Key.TorperfActivated, TorperfDownloader.class);
  }

  private static Configuration conf = new Configuration();

  /**
   * At most one argument.
   * See class description {@link Main}.
   */
  public static void main(String[] args) throws Exception {
    try {
      Path confPath = null;
      if (args == null || args.length == 0) {
        confPath = Paths.get(CONF_FILE);
      } else if (args.length == 1) {
        confPath = Paths.get(args[0]);
      } else {
        printUsage("CollecTor takes at most one argument.");
        return;
      }
      if (!confPath.toFile().exists() || confPath.toFile().length() < 1L) {
        writeDefaultConfig(confPath);
        return;
      } else {
        conf.setWatchableSourceAndLoad(confPath);
      }
      Scheduler.getInstance().scheduleModuleRuns(collecTorMains, conf);
    } catch (ConfigurationException ce) {
      printUsage(ce.getMessage());
      return;
    }
    Runtime.getRuntime().addShutdownHook(new ShutdownHook());
  }

  private static void printUsage(String msg) {
    final String usage = "Usage:\njava -jar collector.jar "
        + "[path/to/configFile]";
    System.out.println(msg + "\n" + usage);
  }

  private static void writeDefaultConfig(Path confPath) {
    try {
      Files.copy(Main.class.getClassLoader().getResource(CONF_FILE)
          .openStream(), confPath, StandardCopyOption.REPLACE_EXISTING);
      printUsage("Could not find config file. In the default "
          + "configuration, we are not configured to read data from any "
          + "data source or write data to any data sink. You need to "
          + "change the configuration (" + CONF_FILE
          + ") and provide at least one data source and one data sink. "
          + "Refer to the manual for more information.");
    } catch (IOException e) {
      log.error("Cannot write default configuration. Reason: " + e, e);
      throw new RuntimeException(e);
    }
  }

}

