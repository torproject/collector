/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import org.torproject.descriptor.LogDescriptor;

/**
 * This interface provides methods for internal use only.
 *
 * @since 2.2.0
 */
public interface InternalLogDescriptor extends LogDescriptor {

  /** Logfile name parts separator. */
  String SEP = "_";

  /**
   * Set the descriptor's bytes.
   *
   * @since 2.2.0
   */
  void setRawDescriptorBytes(byte[] bytes);

  /** Return the descriptor's preferred compression. */
  String getCompressionType();
}

