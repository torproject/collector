/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.RelayServerDescriptor;

import java.nio.file.Paths;

public class ServerDescriptorPersistence
    extends DescriptorPersistence<RelayServerDescriptor> {

  private static final String RELAY_DESCRIPTORS = "relay-descriptors";

  public ServerDescriptorPersistence(RelayServerDescriptor desc,
      long received) {
    super(desc, Annotation.Server.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String file = PersistenceUtils.dateTime(received);
    String[] parts = PersistenceUtils.dateTimeParts(desc.getPublishedMillis());
    this.recentPath = Paths.get(
        RELAY_DESCRIPTORS,
        SERVERDESCS,
        file + DASH + SERVERDESCS).toString();
    String digest = desc.getServerDescriptorDigest();
    this.storagePath = Paths.get(
        RELAY_DESCRIPTORS,
        SERVERDESC,
        parts[0], // year
        parts[1], // month
        digest.substring(0,1),
        digest.substring(1,2),
        digest).toString();
  }

}

