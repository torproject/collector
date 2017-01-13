/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;
import org.torproject.collector.persist.BridgeExtraInfoPersistence;
import org.torproject.collector.persist.BridgeServerDescriptorPersistence;
import org.torproject.collector.persist.ConsensusPersistence;
import org.torproject.collector.persist.DescriptorPersistence;
import org.torproject.collector.persist.ExitlistPersistence;
import org.torproject.collector.persist.ExtraInfoPersistence;
import org.torproject.collector.persist.MicroConsensusPersistence;
import org.torproject.collector.persist.PersistenceUtils;
import org.torproject.collector.persist.ServerDescriptorPersistence;
import org.torproject.collector.persist.StatusPersistence;
import org.torproject.collector.persist.VotePersistence;
import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.RelayExtraInfoDescriptor;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.RelayServerDescriptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** Provides persistence for descriptors based on the descriptor type. */
public class SyncPersistence {

  private static final Logger log
      = LoggerFactory.getLogger(SyncPersistence.class);

  private final Path recentPath;
  private final Path outputPath;
  private final String recentPathName;
  private final String outputPathName;
  private static final String DASH = "-";

  /** Initialize with the given configuration. */
  public SyncPersistence(Configuration conf) throws ConfigurationException {
    recentPath = conf.getPath(Key.RecentPath);
    recentPathName = recentPath.toString();
    outputPath = conf.getPath(Key.OutputPath);
    outputPathName = outputPath.toString();
  }

  /**
   * Stores the list of descriptors in main storage and recent.
   * The storage locations are taken from <code>collector.properties</code>'
   * options <code>OutputPath</code> and <code>RecentPath</code>.
   */
  public void storeDescs(List<Descriptor> descs, String filename,
      long received) {
    for (Descriptor desc : descs) {
      boolean recognizedAndWritten = false;
      for (Class clazz : desc.getClass().getInterfaces()) {
        DescriptorPersistence descPersist = null;
        switch (clazz.getSimpleName()) {
          case "RelayNetworkStatusVote":
            descPersist
                = new VotePersistence((RelayNetworkStatusVote) desc, received);
            break;
          case "RelayNetworkStatusConsensus":
            RelayNetworkStatusConsensus cons =
                (RelayNetworkStatusConsensus) desc;
            if (null == cons.getConsensusFlavor()) {
              descPersist = new ConsensusPersistence(cons, received);
            } else if ("microdesc".equals(cons.getConsensusFlavor())) {
              descPersist = new MicroConsensusPersistence(cons, received);
            }
            break;
          case "RelayServerDescriptor":
            descPersist = new ServerDescriptorPersistence(
                (RelayServerDescriptor) desc, received);
            break;
          case "BridgeExtraInfoDescriptor":
            descPersist = new BridgeExtraInfoPersistence(
                (BridgeExtraInfoDescriptor) desc, received);
            break;
          case "RelayExtraInfoDescriptor":
            descPersist = new ExtraInfoPersistence(
                (RelayExtraInfoDescriptor) desc, received);
            break;
          case "BridgeNetworkStatus": // need to infer authId from filename
            descPersist = new StatusPersistence(
                (BridgeNetworkStatus) desc, filename.split(DASH)[2], received);
            break;
          case "BridgeServerDescriptor":
            descPersist = new BridgeServerDescriptorPersistence(
                (BridgeServerDescriptor) desc, received);
            break;
          case "ExitList": // downloaded is part of desc, which to use?
            descPersist = new ExitlistPersistence((ExitList) desc, received);
            break;
          default:
            log.trace("Invalid descriptor type {} for sync-merge.",
                clazz.getName());
            continue;
        }
        if (null != descPersist) {
          descPersist.storeAll(recentPathName, outputPathName);
          recognizedAndWritten = true;
        }
        break;
      }
      if (!recognizedAndWritten) {
        log.error("Unknown descriptor type {} implementing {}.",
            desc.getClass().getSimpleName(), desc.getClass().getInterfaces());
      }
    }
    try {
      PersistenceUtils.cleanDirectory(recentPath);
    } catch (IOException ioe) {
      log.error("Cleaning of {} failed.", recentPath.toString(), ioe);
    }
  }

}
