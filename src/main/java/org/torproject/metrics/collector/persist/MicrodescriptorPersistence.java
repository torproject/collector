/* Copyright 2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.Microdescriptor;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class MicrodescriptorPersistence
    extends DescriptorPersistence<Microdescriptor> {

  private static final String RELAY_DESCRIPTORS = "relay-descriptors";

  public MicrodescriptorPersistence(Microdescriptor descriptor, long received,
      String year, String month) {
    super(descriptor, Annotation.Microdescriptor.bytes());
    calculatePaths(received, year, month);
  }

  private void calculatePaths(long received, String year, String month) {
    String file = PersistenceUtils.dateTime(received);
    this.recentPath = Paths.get(
        RELAY_DESCRIPTORS, MICRODESCS, "micro",
        file + "-micro-" + year + "-" + month).toString();
    String digest = desc.getDigestSha256Hex();
    this.storagePath = Paths.get(
        RELAY_DESCRIPTORS,
        MICRODESC, year, month, "micro",
        digest.substring(0,1),
        digest.substring(1,2),
        digest).toString();
  }
}

