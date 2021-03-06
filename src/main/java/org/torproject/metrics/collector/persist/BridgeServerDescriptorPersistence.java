/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class BridgeServerDescriptorPersistence
    extends DescriptorPersistence<BridgeServerDescriptor> {

  /**
   * Construct a persistence instance from a previously parsed descriptor.
   */
  public BridgeServerDescriptorPersistence(BridgeServerDescriptor descriptor,
      long received) {
    super(descriptor, Annotation.BridgeServer.bytes());
    this.calculatePaths(
        PersistenceUtils.dateTimeParts(descriptor.getPublishedMillis()),
        PersistenceUtils.dateTime(received),
        descriptor.getDigestSha1Hex().toLowerCase());
  }

  /**
   * Construct a persistence instance from raw descriptor bytes.
   */
  public BridgeServerDescriptorPersistence(byte[] descriptorBytes,
      String publishedString, String receivedString, String descriptorDigest) {
    super(descriptorBytes);
    this.calculatePaths(
        publishedString.split("[ :-]"),
        receivedString,
        descriptorDigest.toLowerCase());
  }

  private void calculatePaths(String[] publishedParts, String receivedString,
      String descriptorDigest) {
    this.recentPath = Paths.get(
        BRIDGEDESCS,
        SERVERDESCS,
        receivedString + DASH + SERVERDESCS).toString();
    this.storagePath = Paths.get(
        BRIDGEDESCS,
        publishedParts[0], // year
        publishedParts[1], // month
        SERVERDESCS,
        descriptorDigest.substring(0, 1),
        descriptorDigest.substring(1, 2),
        descriptorDigest).toString();
  }
}

