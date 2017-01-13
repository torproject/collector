/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

import java.nio.file.Paths;

public class ConsensusPersistence
    extends DescriptorPersistence<RelayNetworkStatusConsensus> {

  private static final String CONSENSUS = "consensus";

  /** Initialize with appropriate annotation and given parameters. */
  public ConsensusPersistence(RelayNetworkStatusConsensus desc, long received) {
    super(desc, Annotation.Consensus.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String fileRecent = PersistenceUtils.dateTime(desc.getValidAfterMillis());
    String fileOut = PersistenceUtils.dateTime(desc.getValidAfterMillis());
    String[] parts = fileOut.split(DASH);
    this.recentPath = Paths.get(
        RELAYDESCS,
        "consensuses",
        fileRecent + DASH + CONSENSUS).toString();
    this.storagePath = Paths.get(
        RELAYDESCS,
        CONSENSUS,
        parts[0], // year
        parts[1], // month
        parts[2], // day
        fileOut + DASH + CONSENSUS).toString();
  }

}

