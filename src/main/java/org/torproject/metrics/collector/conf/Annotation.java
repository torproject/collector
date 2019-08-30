/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.conf;

/** This enum contains all currently valid descriptor annotations. */
public enum Annotation {

  BandwidthFile("@type bandwidth-file 1.0\n"),
  BridgeExtraInfo("@type bridge-extra-info 1.3\n"),
  BridgePoolAssignment("@type bridge-pool-assignment 1.0\n"),
  BridgeServer("@type bridge-server-descriptor 1.2\n"),
  Cert("@type dir-key-certificate-3 1.0\n"),
  Consensus("@type network-status-consensus-3 1.0\n"),
  ExitList("@type tordnsel 1.0\n"),
  ExtraInfo("@type extra-info 1.0\n"),
  MicroConsensus("@type network-status-microdesc-consensus-3 1.0\n"),
  Microdescriptor("@type microdescriptor 1.0\n"),
  Server("@type server-descriptor 1.0\n"),
  Status("@type bridge-network-status 1.2\n"),
  OnionPerf("@type torperf 1.1\n"),
  Vote("@type network-status-vote-3 1.0\n"),
  SnowflakeStats("@type snowflake-stats 1.0\n");

  private final String annotation;
  private final byte[] bytes;

  Annotation(String annotation) {
    this.annotation = annotation;
    this.bytes = annotation.getBytes();
  }

  public byte[] bytes() {
    return bytes;
  }

  @Override
  public String toString() {
    return annotation;
  }
}
