/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.collector.conf.Annotation;
import org.torproject.descriptor.RelayNetworkStatusVote;

import org.apache.commons.codec.digest.DigestUtils;

import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;

public class VotePersistence
    extends DescriptorPersistence<RelayNetworkStatusVote> {

  private static final String VOTE = "vote";
  private static final String VOTES = "votes";

  public VotePersistence(RelayNetworkStatusVote desc, long received) {
    super(desc, Annotation.Vote.bytes());
    calculatePaths(received);
  }

  private void calculatePaths(long received) {
    String fileOut
        = PersistenceUtils.dateTime(desc.getValidAfterMillis());
    String[] parts = fileOut.split(DASH);
    String digest = calcDigestFromBytes(desc.getRawDescriptorBytes());
    fileOut += DASH + VOTE + DASH + desc.getSignatures().get(0).getIdentity()
        + DASH + digest;
    this.recentPath = Paths.get(
        RELAYDESCS,
        VOTES,
        fileOut).toString();
    this.storagePath = Paths.get(
        RELAYDESCS,
        VOTE,
        parts[0], // year
        parts[1], // month
        parts[2], // day
        fileOut).toString();
  }

  /** Calculate a descriptor digest for votes. */
  private static String calcDigestFromBytes(byte[] bytes) {
    String digest = "";
    String startToken = "network-status-version ";
    String sigToken = "directory-signature ";
    try {
      String ascii = new String(bytes, "US-ASCII");
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken);
      if (start >= 0 && sig >= 0 && sig > start) {
        sig += sigToken.length();
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(bytes, start, forDigest, 0, sig - start);
        digest = DigestUtils.shaHex(forDigest).toUpperCase();
      } else {
        log.error("No digest calculation possible.  Returning empty string.");
      }
    } catch (UnsupportedEncodingException uee) {
      log.error("Unsupported encoding.  Returning empty string.", uee);
    }
    return digest;
  }

}

