/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import java.util.Arrays;

/** Builds a non-sanitized bridge network status that comes with an original
 * bridge network status entry (of a bundled and therefore publicly known
 * bridge) by default. */
class NetworkStatusBuilder extends DescriptorBuilder {

  /** Initializes the descriptor builder. */
  NetworkStatusBuilder() {
    this.addAll(Arrays.asList(
        "published 2016-06-30 23:40:28",
        "flag-thresholds stable-uptime=807660 stable-mtbf=1425164 "
            + "fast-speed=47000 guard-wfu=98.000% guard-tk=691200 "
            + "guard-bw-inc-exits=400000 guard-bw-exc-exits=402000 "
            + "enough-mtbf=1 ignoring-advertised-bws=0",
        "r MeekGoogle RtSnEZe4+lFagmxrAXxSL+JkZVs "
            + "g+M7Ww+lGKmv6NW9GRmvzLOiR0Y 2016-06-30 21:43:52 "
            + "198.50.200.131 8008 0",
        "s Fast Running Stable Valid",
        "w Bandwidth=56",
        "p reject 1-65535"));
  }
}

