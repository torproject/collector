/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

import java.nio.file.Paths;

public class MicroConsensusPersistence
    extends DescriptorPersistence<RelayNetworkStatusConsensus> {

  private static final String CONSENSUS_MICRODESC = "consensus-microdesc";
  private static final String MICRODESC = "microdesc";

  /** Initialize with appropriate annotation and given parameters. */
  public MicroConsensusPersistence(RelayNetworkStatusConsensus desc,
      long received) {
    super(desc, Annotation.MicroConsensus.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String fileRecent = PersistenceUtils.dateTime(desc.getValidAfterMillis());
    String fileOut = PersistenceUtils.dateTime(desc.getValidAfterMillis());
    String[] parts = fileOut.split(DASH);
    this.recentPath = Paths.get(
        RELAYDESCS,
        MICRODESCS,
        CONSENSUS_MICRODESC,
        fileRecent + DASH + CONSENSUS_MICRODESC).toString();
    this.storagePath = Paths.get(
        RELAYDESCS,
        MICRODESC,
        parts[0],
        parts[1],
        CONSENSUS_MICRODESC,
        parts[2],
        fileOut + DASH + CONSENSUS_MICRODESC).toString();
  }

}

