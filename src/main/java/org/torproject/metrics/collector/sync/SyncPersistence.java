/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.sync;

import org.torproject.descriptor.BandwidthFile;
import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgePoolAssignment;
import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.descriptor.BridgedbMetrics;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.RelayExtraInfoDescriptor;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.RelayServerDescriptor;
import org.torproject.descriptor.SnowflakeStats;
import org.torproject.descriptor.TorperfResult;
import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;
import org.torproject.metrics.collector.persist.BandwidthFilePersistence;
import org.torproject.metrics.collector.persist.BridgeExtraInfoPersistence;
import org.torproject.metrics.collector.persist.BridgePoolAssignmentPersistence;
import org.torproject.metrics.collector.persist.BridgeServerDescriptorPersistence;
import org.torproject.metrics.collector.persist.BridgedbMetricsPersistence;
import org.torproject.metrics.collector.persist.ConsensusPersistence;
import org.torproject.metrics.collector.persist.DescriptorPersistence;
import org.torproject.metrics.collector.persist.ExitlistPersistence;
import org.torproject.metrics.collector.persist.ExtraInfoPersistence;
import org.torproject.metrics.collector.persist.MicroConsensusPersistence;
import org.torproject.metrics.collector.persist.OnionPerfPersistence;
import org.torproject.metrics.collector.persist.PersistenceUtils;
import org.torproject.metrics.collector.persist.ServerDescriptorPersistence;
import org.torproject.metrics.collector.persist.SnowflakeStatsPersistence;
import org.torproject.metrics.collector.persist.StatusPersistence;
import org.torproject.metrics.collector.persist.VotePersistence;
import org.torproject.metrics.collector.persist.WebServerAccessLogPersistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;

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
   * Cleans the directory in {@code RecentPath} after storing descriptors.
   */
  public void cleanDirectory() {
    try {
      PersistenceUtils.cleanDirectory(recentPath);
    } catch (IOException ioe) {
      log.error("Cleaning of {} failed.", recentPath.toString(), ioe);
    }
  }

  /**
   * Stores descriptors in main storage and recent.
   * The storage locations are taken from {@code collector.properties}'
   * options {@code OutputPath} and {@code RecentPath}.
   */
  public void storeDescs(Iterable<Descriptor> descs, long received) {
    for (Descriptor desc : descs) {
      storeDesc(desc, received);
    }
  }

  /**
   * Stores a descriptor in main storage and recent.
   * The storage locations are taken from {@code collector.properties}'
   * options {@code OutputPath} and {@code RecentPath}.
   */
  public void storeDesc(Descriptor desc, long received) {
    String filename = desc.getDescriptorFile().getName();
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
          String[] filenameParts = filename.split(DASH);
          if (filenameParts.length < 3) {
            log.error("Invalid BridgeNetworkStatus; skipping: {}.", filename);
            break;
          }
          descPersist = new StatusPersistence(
              (BridgeNetworkStatus) desc, filenameParts[2], received);
          break;
        case "BridgeServerDescriptor":
          descPersist = new BridgeServerDescriptorPersistence(
              (BridgeServerDescriptor) desc, received);
          break;
        case "BridgePoolAssignment":
          descPersist = new BridgePoolAssignmentPersistence(
              (BridgePoolAssignment) desc);
          break;
        case "ExitList": // downloaded is part of desc, which to use?
          descPersist = new ExitlistPersistence((ExitList) desc, received);
          break;
        case "TorperfResult":
          descPersist = new OnionPerfPersistence((TorperfResult) desc);
          break;
        case "WebServerAccessLog":
          descPersist = new WebServerAccessLogPersistence(
              (WebServerAccessLog) desc);
          break;
        case "BandwidthFile":
          descPersist = new BandwidthFilePersistence((BandwidthFile) desc);
          break;
        case "SnowflakeStats":
          descPersist = new SnowflakeStatsPersistence((SnowflakeStats) desc);
          break;
        case "BridgedbStats":
          descPersist = new BridgedbMetricsPersistence((BridgedbMetrics) desc);
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
}

