/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

/** Interface for decisions to be made in the sync-process. */
public interface Criterium<T> {

  /** Determine, if the given object of type T fulfills the Criterium. */
  public boolean applies(T object);

}

