/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class BridgeServerDescriptorPersistence
    extends DescriptorPersistence<BridgeServerDescriptor> {

  public BridgeServerDescriptorPersistence(BridgeServerDescriptor desc,
      long received) {
    super(desc, Annotation.BridgeServer.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String file = PersistenceUtils.dateTime(received);
    String[] parts = PersistenceUtils.dateTimeParts(desc.getPublishedMillis());
    this.recentPath = Paths.get(
        BRIDGEDESCS,
        SERVERDESCS,
        file + DASH + SERVERDESCS).toString();
    String digest = desc.getDigestSha1Hex().toLowerCase();
    this.storagePath = Paths.get(
        BRIDGEDESCS,
        parts[0], // year
        parts[1], // month
        SERVERDESCS,
        digest.substring(0,1),
        digest.substring(1,2),
        digest).toString();
  }

}

