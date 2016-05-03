/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector;

import org.torproject.collector.bridgedescs.SanitizedBridgesWriter;
import org.torproject.collector.bridgepools.BridgePoolAssignmentsProcessor;
import org.torproject.collector.exitlists.ExitListDownloader;
import org.torproject.collector.index.CreateIndexJson;
import org.torproject.collector.relaydescs.ArchiveWriter;
import org.torproject.collector.torperf.TorperfDownloader;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Main class for starting a CollecTor instance.
 * <br>
 * Run without arguments in order to read the usage information, i.e.
 * <br>
 * <code>java -jar collector.jar</code>
 */
public class Main {

  private static Logger log = Logger.getLogger(Main.class.getName());

  /** All possible main classes.
   * If a new CollecTorMain class is available, just add it to this map.
   */
  private static final Map<String, Class> collecTorMains = new HashMap<>();

  static { // add a new main class here
    collecTorMains.put("bridgedescs", SanitizedBridgesWriter.class);
    collecTorMains.put("bridgepools", BridgePoolAssignmentsProcessor.class);
    collecTorMains.put("exitlists", ExitListDownloader.class);
    collecTorMains.put("updateindex", CreateIndexJson.class);
    collecTorMains.put("relaydescs", ArchiveWriter.class);
    collecTorMains.put("torperf", TorperfDownloader.class);
  }

  private static final String modules = collecTorMains.keySet().toString()
      .replace("[", "").replace("]", "").replaceAll(", ", "|");

  /**
   * One argument is necessary.
   * See class description {@link Main}.
   */
  public static void main(String[] args) {
    if (null == args || args.length != 1) {
      printUsageAndExit("CollecTor needs exactly one argument.");
    } else {
      invokeGivenMainAndExit(args[0]);
    }
  }

  private static void printUsageAndExit(String msg) {
    final String usage = "Usage:\njava -jar collector.jar "
        + "<" + modules + ">";
    System.out.println(msg + "\n" + usage);
    System.exit(0);
  }

  private static void invokeGivenMainAndExit(String mainId) {
    Class clazz = collecTorMains.get(mainId);
    if (null == clazz) {
      printUsageAndExit("Unknown argument: " + mainId);
    }
    invokeMainOnClassAndExit(clazz);
  }

  private static void invokeMainOnClassAndExit(Class clazz) {
    try {
      clazz.getMethod("main", new Class[] { String[].class })
          .invoke(null, (Object) new String[]{});
      System.exit(0);
    } catch (NoSuchMethodException | IllegalAccessException
       | InvocationTargetException e) {
      log.severe("Cannot invoke 'main' method on "
          + clazz.getName() + ". " + e);
    }
  }
}

