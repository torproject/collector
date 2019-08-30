/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BridgePoolAssignment;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class BridgePoolAssignmentPersistence
    extends DescriptorPersistence<BridgePoolAssignment> {

  public BridgePoolAssignmentPersistence(BridgePoolAssignment desc) {
    super(desc, Annotation.BridgePoolAssignment.bytes());
    calculatePaths();
  }

  private void calculatePaths() {
    String file = PersistenceUtils.dateTime(desc.getPublishedMillis());
    String[] parts = file.split(DASH);
    this.recentPath = Paths.get(
        BRIDGEPOOLASSIGNMENTS,
        file).toString();
    this.storagePath = Paths.get(
        BRIDGEPOOLASSIGNMENTS,
        parts[0], // year
        parts[1], // month
        parts[2], // day
        file).toString();
  }

}

