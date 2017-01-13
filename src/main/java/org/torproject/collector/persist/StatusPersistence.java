/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.BridgeNetworkStatus;

import java.nio.file.Paths;

public class StatusPersistence
    extends DescriptorPersistence<BridgeNetworkStatus> {

  private static final String STATUSES = "statuses";

  public StatusPersistence(BridgeNetworkStatus desc,
      String authId, long received) {
    super(desc, Annotation.Status.bytes());
    calculatePaths(authId, received);
  }

  private void calculatePaths(String authId, long received) {
    String[] partsOut = PersistenceUtils.dateTimeParts(
        desc.getPublishedMillis());
    String fileOut = partsOut[0] + partsOut[1] + partsOut[2] + DASH
        + partsOut[3] + partsOut[4] + partsOut[5] + DASH + authId;
    this.recentPath = Paths.get(
        BRIDGEDESCS,
        STATUSES,
        fileOut).toString();
    this.storagePath = Paths.get(
        BRIDGEDESCS,
        partsOut[0], // year
        partsOut[1], // month
        STATUSES,
        partsOut[2], // day
        fileOut).toString();
  }

}

