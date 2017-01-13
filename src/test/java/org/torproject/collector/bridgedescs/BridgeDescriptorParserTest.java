/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import org.torproject.collector.conf.Configuration;

import org.junit.Test;

public class BridgeDescriptorParserTest {

  @Test(expected = IllegalArgumentException.class)
  public void testNullArgForConstructor() throws Exception {
    new BridgeDescriptorParser(null);
  }

  @Test(expected = NullPointerException.class)
  public void testNullData() throws Exception {
    BridgeDescriptorParser bdp = new BridgeDescriptorParser(
        new SanitizedBridgesWriter(new Configuration()));
    bdp.parse(null, "", "");
  }

  @Test
  /* Empty data is not passed down to the sanitized writer.
   * This test passes when there is no exception. */
  public void testDataEmpty() throws Exception {
    BridgeDescriptorParser bdp = new BridgeDescriptorParser(
        new SanitizedBridgesWriter(new Configuration()));
    bdp.parse(new byte[]{}, null, null);
  }

  @Test(expected = NullPointerException.class)
  /* The SanitizedBridgesWriter wasn't initialized sufficiently.
   * Actually that should be corrected in SanitizedBridgesWriter
   * at some point, but that's a bigger rewrite. */
  public void testMinimalData() throws Exception {
    BridgeDescriptorParser bdp = new BridgeDescriptorParser(
        new SanitizedBridgesWriter(new Configuration()));
    bdp.parse(new byte[]{0}, "2010-10-10 10:10:10", null);
  }

}
