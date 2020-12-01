/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class BridgeNetworkStatusPersistence
    extends DescriptorPersistence<BridgeNetworkStatus> {

  private static final String STATUSES = "statuses";

  /**
   * Construct a persistence instance from a previously parsed descriptor.
   */
  public BridgeNetworkStatusPersistence(BridgeNetworkStatus descriptor,
      String authorityFingerprint) {
    super(descriptor, Annotation.Status.bytes());
    this.calculatePaths(
        PersistenceUtils.dateTimeParts(descriptor.getPublishedMillis()),
        authorityFingerprint);
  }

  /**
   * Construct a persistence instance from raw descriptor bytes.
   */
  public BridgeNetworkStatusPersistence(byte[] descriptorBytes,
      String published, String authorityFingerprint) {
    super(descriptorBytes);
    this.calculatePaths(
        published.split("[ :-]"),
        authorityFingerprint);
  }

  private void calculatePaths(String[] publishedParts,
      String authorityFingerprint) {
    String fileOut = publishedParts[0] + publishedParts[1] + publishedParts[2]
        + DASH + publishedParts[3] + publishedParts[4] + publishedParts[5]
        + DASH + authorityFingerprint;
    this.recentPath = Paths.get(
        BRIDGEDESCS,
        STATUSES,
        fileOut).toString();
    this.storagePath = Paths.get(
        BRIDGEDESCS,
        publishedParts[0], // year
        publishedParts[1], // month
        STATUSES,
        publishedParts[2], // day
        fileOut).toString();
  }
}

