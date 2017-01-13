/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.persist;

import org.torproject.descriptor.Descriptor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public abstract class DescriptorPersistence<T extends Descriptor> {

  protected static final Logger log = LoggerFactory.getLogger(
      DescriptorPersistence.class);

  protected static final String BRIDGEDESCS = "bridge-descriptors";
  protected static final String DASH = "-";
  protected static final String MICRODESC = "microdesc";
  protected static final String MICRODESCS = "microdescs";
  protected static final String RELAYDESCS = "relay-descriptors";
  protected static final String EXTRA_INFO = "extra-info";
  protected static final String EXTRA_INFOS = "extra-infos";
  protected static final String SERVERDESC = "server-descriptor";
  protected static final String SERVERDESCS = "server-descriptors";

  protected final T desc;
  protected final byte[] annotation;
  protected String storagePath;
  protected String recentPath;

  /** Initializes the paths for storing descriptors of type <code>T</code>. */
  protected DescriptorPersistence(T desc, byte[] annotation) {
    this.desc = desc;
    this.annotation = annotation;
  }

  /** Stores the descriptor to all locations.
   * First attempt to store the 'out' path, if that works store to 'recent'.
   * Returns <code>true</code>, if both were written. */
  public boolean storeAll(String recentRoot, String outRoot) {
    return storeAll(recentRoot, outRoot, StandardOpenOption.APPEND,
        StandardOpenOption.CREATE_NEW);
  }

  /** Stores the descriptor to all locations.
   * First attempt to store the 'out' path, if that works store to 'recent'.
   * Returns <code>true</code>, if both were written. */
  public boolean storeAll(String recentRoot, String outRoot,
      StandardOpenOption optionRecent, StandardOpenOption optionOut) {
    if (storeOut(outRoot, optionOut)) {
      return storeRecent(recentRoot, optionRecent);
    }
    return false;
  }

  /** Stores the descriptor in recent.
   * Creates a new file or appends to an existing file. */
  public boolean storeRecent(String recentRoot) {
    return storeRecent(recentRoot, StandardOpenOption.APPEND);
  }

  /** Stores the descriptor in recent.
   * Creates, replaces, or appends according to the given option.
   * Returns <code>true</code>, if the file was written. */
  public boolean storeRecent(String recentRoot, StandardOpenOption option) {
    return PersistenceUtils.storeToFileSystem(annotation,
        desc.getRawDescriptorBytes(), Paths.get(recentRoot, getRecentPath()),
        option, true);
  }

  /** Stores the descriptor in out (i.e. internal storage).
   * Only writes, if the file doesn't exist yet.
   * Returns <code>true</code>, if the file was written. */
  public boolean storeOut(String outRoot) {
    return storeOut(outRoot, StandardOpenOption.CREATE_NEW);
  }

  /** Stores the descriptor in out (i.e. internal storage).
   * Creates, replaces, or appends according to the given option.
   * Returns <code>true</code>, if the file was written. */
  public boolean storeOut(String outRoot, StandardOpenOption option) {
    return PersistenceUtils.storeToFileSystem(annotation,
        desc.getRawDescriptorBytes(), Paths.get(outRoot, getStoragePath()),
        option);
  }

  /** Return the final storage location inside storage. */
  public String getStoragePath() {
    if (null == storagePath) {
      throw new RuntimeException("Storage path not initialized!");
    }
    return storagePath;
  }

  /** Return the final location for 'recent' descriptors. */
  public String getRecentPath() {
    if (null == recentPath) {
      throw new RuntimeException("Recent path not initialized!");
    }
    return recentPath;
  }

}

