/* Copyright 2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.DirectoryKeyCertificate;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;

public class DirectoryKeyCertificatePersistence
    extends DescriptorPersistence<DirectoryKeyCertificate> {

  public DirectoryKeyCertificatePersistence(
      DirectoryKeyCertificate descriptor) {
    super(descriptor, Annotation.Cert.bytes());
    this.calculatePaths();
  }

  private void calculatePaths() {
    String fileName = this.desc.getFingerprint().toUpperCase() + "-"
        + PersistenceUtils.dateTime(this.desc.getDirKeyPublishedMillis());
    this.recentPath = Paths.get(RELAYDESCS, "certs", fileName).toString();
    this.storagePath = this.recentPath;
  }
}

