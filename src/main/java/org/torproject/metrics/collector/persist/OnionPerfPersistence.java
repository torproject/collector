/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.TorperfResult;
import org.torproject.metrics.collector.conf.Annotation;

import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class OnionPerfPersistence
    extends DescriptorPersistence<TorperfResult> {

  private static final String ONIONPERF = "torperf";

  public OnionPerfPersistence(TorperfResult desc) {
    super(desc, Annotation.OnionPerf.bytes());
    calculatePaths();
  }

  private void calculatePaths() {
    String[] parts = PersistenceUtils.dateTimeParts(desc.getStartMillis());
    String name =  desc.getSource() + DASH + desc.getFileSize() + DASH
        + parts[0] + DASH + parts[1] + DASH + parts[2] + ".tpf";
    this.recentPath = Paths.get(ONIONPERF, name).toString();
    this.storagePath = Paths.get(
        ONIONPERF,
        parts[0], // year
        parts[1], // month
        parts[2], // day
        name).toString();
  }

  /** OnionPerf default storage appends. */
  @Override
  public boolean storeOut(String outRoot) {
    return super.storeOut(outRoot, StandardOpenOption.APPEND);
  }

  /** OnionPerf default storage appends. */
  @Override
  public boolean storeAll(String recentRoot, String outRoot) {
    return super.storeAll(recentRoot, outRoot, StandardOpenOption.APPEND,
        StandardOpenOption.APPEND);
  }

}

