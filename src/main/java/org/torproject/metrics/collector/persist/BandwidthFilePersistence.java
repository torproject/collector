/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.BandwidthFile;
import org.torproject.metrics.collector.conf.Annotation;

import org.apache.commons.codec.digest.DigestUtils;

import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public class BandwidthFilePersistence
    extends DescriptorPersistence<BandwidthFile> {

  private static final String BANDWIDTH = "bandwidth";
  private static final String BANDWIDTHS = "bandwidths";

  public BandwidthFilePersistence(BandwidthFile desc) {
    super(desc, Annotation.BandwidthFile.bytes());
    calculatePaths();
  }

  private void calculatePaths() {
    LocalDateTime fileCreatedOrTimestamp = this.desc.fileCreated()
        .orElse(this.desc.timestamp());
    DateTimeFormatter directoriesFormatter = DateTimeFormatter
        .ofPattern("uuuu/MM/dd").withZone(ZoneOffset.UTC);
    String[] directories = fileCreatedOrTimestamp.format(directoriesFormatter)
        .split("/");
    DateTimeFormatter fileFormatter = DateTimeFormatter
        .ofPattern("uuuu-MM-dd-HH-mm-ss").withZone(ZoneOffset.UTC);
    String bandwidthFileDigest = calcDigestFromBytes(
        this.desc.getRawDescriptorBytes());
    String fileOut = fileCreatedOrTimestamp.format(fileFormatter)
        + "-bandwidth-" + bandwidthFileDigest;
    this.recentPath = Paths.get(RELAYDESCS, BANDWIDTHS, fileOut).toString();
    this.storagePath = Paths.get(RELAYDESCS, BANDWIDTH, directories[0],
        directories[1], directories[2], fileOut).toString();
  }

  /** Calculate a digest for bandwidth files. */
  private static String calcDigestFromBytes(byte[] bytes) {
    String digest = "";
    int start = 0;
    while (start < bytes.length && bytes[start] == (byte) '@') {
      do {
        start++;
      } while (start < bytes.length && bytes[start] != (byte) '\n');
      start++;
    }
    if (start < bytes.length) {
      byte[] forDigest = new byte[bytes.length - start];
      System.arraycopy(bytes, start, forDigest, 0, forDigest.length);
      digest = DigestUtils.sha256Hex(forDigest).toUpperCase();
    } else {
      log.error("No digest calculation possible.  Returning empty string.");
    }
    return digest;
  }
}

