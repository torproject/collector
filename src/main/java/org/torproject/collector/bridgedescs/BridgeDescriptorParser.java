/* Copyright 2010--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import org.torproject.collector.conf.ConfigurationException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;

public class BridgeDescriptorParser {

  private SanitizedBridgesWriter sbw;

  private static final Logger logger = LoggerFactory.getLogger(
      BridgeDescriptorParser.class);

  /** Initializes a new bridge descriptor parser and links it to a
   * sanitized bridges writer to sanitize and store bridge descriptors. */
  public BridgeDescriptorParser(SanitizedBridgesWriter sbw) {
    if (null == sbw) {
      throw new IllegalArgumentException("SanitizedBridgesWriter has to be "
          + "provided, but was null.");
    }
    this.sbw = sbw;
  }

  /** Parses the first line of the given descriptor data to determine the
   * descriptor type and passes it to the sanitized bridges writer. */
  public void parse(byte[] allData, String dateTime,
      String authorityFingerprint) throws ConfigurationException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(allData, "US-ASCII")));
      String line = br.readLine();
      if (line == null) {
        return;
      }
      if (line.startsWith("router ")) {
        this.sbw.sanitizeAndStoreServerDescriptor(allData);
      } else if (line.startsWith("extra-info ")) {
        this.sbw.sanitizeAndStoreExtraInfoDescriptor(allData);
      } else {
        this.sbw.sanitizeAndStoreNetworkStatus(allData, dateTime,
            authorityFingerprint);
      }
    } catch (IOException e) {
      logger.warn("Could not parse or write bridge descriptor.", e);
      return;
    }
  }
}

