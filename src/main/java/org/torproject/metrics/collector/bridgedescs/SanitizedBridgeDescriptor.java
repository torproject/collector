/* Copyright 2010--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.bridgedescs;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

public abstract class SanitizedBridgeDescriptor {

  private static final Logger logger = LoggerFactory.getLogger(
      SanitizedBridgeDescriptor.class);

  protected byte[] originalBytes;

  protected SensitivePartsSanitizer sensitivePartsSanitizer;

  protected byte[] sanitizedBytes;

  protected String publishedString;

  SanitizedBridgeDescriptor(byte[] originalBytes,
      SensitivePartsSanitizer sensitivePartsSanitizer) {
    this.originalBytes = originalBytes;
    this.sensitivePartsSanitizer = sensitivePartsSanitizer;
  }

  protected String parseMasterKeyEd25519FromIdentityEd25519(
      String identityEd25519Base64) {
    byte[] identityEd25519 = Base64.decodeBase64(identityEd25519Base64);
    if (identityEd25519.length < 40) {
      logger.warn("Invalid length of identity-ed25519 (in bytes): {}",
          identityEd25519.length);
    } else if (identityEd25519[0] != 0x01) {
      logger.warn("Unknown version in identity-ed25519: {}",
          identityEd25519[0]);
    } else if (identityEd25519[1] != 0x04) {
      logger.warn("Unknown cert type in identity-ed25519: {}",
          identityEd25519[1]);
    } else if (identityEd25519[6] != 0x01) {
      logger.warn("Unknown certified key type in identity-ed25519: {}",
          identityEd25519[1]);
    } else if (identityEd25519[39] == 0x00) {
      logger.warn("No extensions in identity-ed25519 (which "
              + "would contain the encoded master-key-ed25519): {}",
          identityEd25519[39]);
    } else {
      int extensionStart = 40;
      for (int i = 0; i < (int) identityEd25519[39]; i++) {
        if (identityEd25519.length < extensionStart + 4) {
          logger.warn("Invalid extension with id {} in identity-ed25519.", i);
          break;
        }
        int extensionLength = identityEd25519[extensionStart];
        extensionLength <<= 8;
        extensionLength += identityEd25519[extensionStart + 1];
        int extensionType = identityEd25519[extensionStart + 2];
        if (extensionLength == 32 && extensionType == 4) {
          if (identityEd25519.length < extensionStart + 4 + 32) {
            logger.warn("Invalid extension with id {} in identity-ed25519.", i);
            break;
          }
          byte[] masterKeyEd25519 = new byte[32];
          System.arraycopy(identityEd25519, extensionStart + 4,
              masterKeyEd25519, 0, masterKeyEd25519.length);
          String masterKeyEd25519Base64 = Base64.encodeBase64String(
              masterKeyEd25519);
          return masterKeyEd25519Base64.replaceAll("=", "");
        }
        extensionStart += 4 + extensionLength;
      }
    }
    logger.warn("Unable to locate master-key-ed25519 in identity-ed25519.");
    return null;
  }

  protected String computeDescriptorDigest(byte[] descriptorBytes,
      String startToken, String sigToken) {
    String descriptorDigest = null;
    String ascii = new String(descriptorBytes, StandardCharsets.US_ASCII);
    int start = ascii.indexOf(startToken);
    int sig = ascii.indexOf(sigToken) + sigToken.length();
    if (start >= 0 && sig >= 0 && sig > start) {
      byte[] forDigest = new byte[sig - start];
      System.arraycopy(descriptorBytes, start, forDigest, 0, sig - start);
      descriptorDigest = DigestUtils.sha1Hex(DigestUtils.sha1(forDigest));
    }
    if (descriptorDigest == null) {
      logger.warn("Could not calculate extra-info descriptor digest.");
    }
    return descriptorDigest;
  }

  protected String computeSha256Base64Digest(byte[] descriptorBytes,
      String startToken, String sigToken) {
    String descriptorDigestSha256Base64 = null;
    String ascii = new String(descriptorBytes, StandardCharsets.US_ASCII);
    int start = ascii.indexOf(startToken);
    int sig = ascii.indexOf(sigToken) + sigToken.length();
    if (start >= 0 && sig >= 0 && sig > start) {
      byte[] forDigest = new byte[sig - start];
      System.arraycopy(descriptorBytes, start, forDigest, 0, sig - start);
      descriptorDigestSha256Base64 = Base64.encodeBase64String(
          DigestUtils.sha256(DigestUtils.sha256(forDigest)))
          .replaceAll("=", "");
    }
    if (descriptorDigestSha256Base64 == null) {
      logger.warn("Could not calculate extra-info "
          + "descriptor SHA256 digest.");
    }
    return descriptorDigestSha256Base64;
  }
}

