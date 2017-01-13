/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.RelayExtraInfoDescriptor;

import java.nio.file.Paths;

public class ExtraInfoPersistence
    extends DescriptorPersistence<RelayExtraInfoDescriptor> {

  public ExtraInfoPersistence(RelayExtraInfoDescriptor desc,
      long received) {
    super(desc, Annotation.ExtraInfo.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String file = PersistenceUtils.dateTime(received);
    String[] parts = PersistenceUtils.dateTimeParts(desc.getPublishedMillis());
    this.recentPath = Paths.get(
        RELAYDESCS,
        EXTRA_INFOS,
        file + DASH + EXTRA_INFOS).toString();
    String digest = desc.getExtraInfoDigest();
    this.storagePath = Paths.get(
        RELAYDESCS,
        EXTRA_INFO,
        parts[0],
        parts[1],
        digest.substring(0,1),
        digest.substring(1,2),
        digest).toString();
  }

}

