/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.TorperfResult;
import org.torproject.metrics.collector.conf.Annotation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class OnionPerfPersistence
    extends DescriptorPersistence<TorperfResult> {

  private static final Logger logger
      = LoggerFactory.getLogger(OnionPerfPersistence.class);

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

  /** If the original descriptor file was a .tpf file, append the parsed Torperf
   * result to the destination .tpf file, but if it was a .json.xz file, just
   * copy over the entire file, unless it already exists. */
  @Override
  public boolean storeOut(String outRoot, StandardOpenOption option) {
    if (desc.getDescriptorFile().getName().endsWith(".tpf")) {
      return super.storeOut(outRoot, StandardOpenOption.APPEND);
    } else {
      String fileName = desc.getDescriptorFile().getName();
      String[] dateParts = fileName.split("\\.")[0].split("-");
      return this.copyIfNotExists(
          Paths.get(outRoot,
              "onionperf",
              dateParts[0], // year
              dateParts[1], // month
              dateParts[2], // day
              fileName));
    }
  }

  /** If the original descriptor file was a .tpf file, append the parsed Torperf
   * result to the destination .tpf file, but if it was a .json.xz file, just
   * copy over the entire file, unless it already exists. */
  @Override
  public boolean storeRecent(String recentRoot, StandardOpenOption option) {
    if (desc.getDescriptorFile().getName().endsWith(".tpf")) {
      return super.storeRecent(recentRoot, StandardOpenOption.APPEND);
    } else {
      String fileName = desc.getDescriptorFile().getName();
      return this.copyIfNotExists(
          Paths.get(recentRoot,
          "onionperf",
          fileName));
    }
  }

  private boolean copyIfNotExists(Path destinationFile) {
    if (Files.exists(destinationFile)) {
      return false;
    }
    Path originalFile = this.desc.getDescriptorFile().toPath();
    try {
      Files.createDirectories(destinationFile.getParent());
      Files.copy(originalFile, destinationFile);
    } catch (IOException e) {
      logger.warn("Unable to copy file.", e);
      return false;
    }
    return true;
  }
}

