/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.conf;

/** This enum contains all currently valid descriptor annotations. */
public enum Annotation {

  BridgeExtraInfo("@type bridge-extra-info 1.3\n"),
  BridgeServer("@type bridge-server-descriptor 1.2\n"),
  Cert("@type dir-key-certificate-3 1.0\n"),
  Consensus("@type network-status-consensus-3 1.0\n"),
  ExitList("@type tordnsel 1.0\n"),
  ExtraInfo("@type extra-info 1.0\n"),
  MicroConsensus("@type network-status-microdesc-consensus-3 1.0\n"),
  Microdescriptor("@type microdescriptor 1.0\n"),
  Server("@type server-descriptor 1.0\n"),
  Status("@type bridge-network-status 1.1\n"),
  Torperf("@type torperf 1.0\n"),
  Vote("@type network-status-vote-3 1.0\n");

  private final String annotation;
  private final byte[] bytes;

  private Annotation(String annotation) {
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
