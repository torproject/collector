/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.collector.bridgedescs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BridgeDescriptorParser {
  private SanitizedBridgesWriter sbw;
  private Logger logger;
  public BridgeDescriptorParser(SanitizedBridgesWriter sbw) {
    this.sbw = sbw;
    this.logger =
        Logger.getLogger(BridgeDescriptorParser.class.getName());
  }
  public void parse(byte[] allData, String dateTime) {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(allData, "US-ASCII")));
      String line = br.readLine();
      if (line == null) {
        return;
      } else if (line.startsWith("router ")) {
        if (this.sbw != null) {
          this.sbw.sanitizeAndStoreServerDescriptor(allData);
        }
      } else if (line.startsWith("extra-info ")) {
        if (this.sbw != null) {
          this.sbw.sanitizeAndStoreExtraInfoDescriptor(allData);
        }
      } else {
        if (this.sbw != null) {
          this.sbw.sanitizeAndStoreNetworkStatus(allData, dateTime);
        }
      }
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not parse bridge descriptor.",
          e);
      return;
    }
  }
}

