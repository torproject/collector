/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.BridgeExtraInfoDescriptor;

import java.nio.file.Paths;

public class BridgeExtraInfoPersistence
    extends DescriptorPersistence<BridgeExtraInfoDescriptor> {

  public BridgeExtraInfoPersistence(BridgeExtraInfoDescriptor desc,
      long received) {
    super(desc, Annotation.BridgeExtraInfo.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String file = PersistenceUtils.dateTime(received);
    String[] parts = PersistenceUtils.dateTimeParts(desc.getPublishedMillis());
    this.recentPath = Paths.get(
        BRIDGEDESCS,
        EXTRA_INFOS,
        file + DASH + EXTRA_INFOS).toString();
    String digest = desc.getExtraInfoDigest().toLowerCase();
    this.storagePath = Paths.get(
        BRIDGEDESCS,
        parts[0], // year
        parts[1], // month
        EXTRA_INFOS,
        digest.substring(0,1),
        digest.substring(1,2),
        digest).toString();
  }

}

