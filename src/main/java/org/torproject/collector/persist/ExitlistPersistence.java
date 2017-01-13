/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.ExitList;

import java.nio.file.Paths;

public class ExitlistPersistence
    extends DescriptorPersistence<ExitList> {

  private static final String EXITLISTS = "exit-lists";

  public ExitlistPersistence(ExitList desc, long received) {
    super(desc, Annotation.ExitList.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    this.recentPath = Paths.get(
        EXITLISTS,
        PersistenceUtils.dateTime(desc.getDownloadedMillis())).toString();
    String[] parts = PersistenceUtils.dateTimeParts(desc.getDownloadedMillis());
    this.storagePath = Paths.get(
        EXITLISTS,
        parts[0], // year
        parts[1], // month
        parts[2], // day
        PersistenceUtils.dateTime(desc.getDownloadedMillis())).toString();
  }

}

