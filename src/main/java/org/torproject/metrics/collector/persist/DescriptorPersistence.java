/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.Descriptor;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

public abstract class DescriptorPersistence<T extends Descriptor> {

  protected static final String BRIDGEDESCS = "bridge-descriptors";
  protected static final String BRIDGEPOOLASSIGNMENTS
      = "bridge-pool-assignments";
  protected static final String BRIDGEDBSTATS = "bridgedb-stats";
  protected static final String DASH = "-";
  protected static final String DOT = ".";
  protected static final String MICRODESC = "microdesc";
  protected static final String MICRODESCS = "microdescs";
  protected static final String RELAYDESCS = "relay-descriptors";
  protected static final String EXTRA_INFO = "extra-info";
  protected static final String EXTRA_INFOS = "extra-infos";
  protected static final String SERVERDESC = "server-descriptor";
  protected static final String SERVERDESCS = "server-descriptors";
  protected static final String WEBSTATS = "webstats";

  protected T desc;

  protected final byte[] annotationBytes;
  protected final byte[] descriptorBytes;
  protected String storagePath;
  protected String recentPath;

  protected static final byte[] EMPTY_ANNOTATION = new byte[0];

  /**
   * Initializes the paths for storing descriptors of type {@code T}.
   */
  protected DescriptorPersistence(T descriptor, byte[] defaultAnnotationBytes) {
    this.desc = descriptor;
    List<String> annotations = descriptor.getAnnotations();
    if (annotations.isEmpty()) {
      this.annotationBytes = defaultAnnotationBytes;
    } else {
      StringBuilder sb = new StringBuilder();
      for (String annotation : annotations) {
        sb.append(annotation).append("\n");
      }
      this.annotationBytes = sb.toString().getBytes();
    }
    this.descriptorBytes = descriptor.getRawDescriptorBytes();
  }

  protected DescriptorPersistence(byte[] descriptorBytes) {
    this.annotationBytes = EMPTY_ANNOTATION;
    this.descriptorBytes = descriptorBytes;
  }

  /** Stores the descriptor to all locations.
   * First attempt to store the 'out' path, if that works store to 'recent'.
   * Returns {@code true}, if both were written. */
  public boolean storeAll(Path recentRoot, Path outRoot) {
    return storeAll(recentRoot.toString(), outRoot.toString());
  }

  /** Stores the descriptor to all locations.
   * First attempt to store the 'out' path, if that works store to 'recent'.
   * Returns {@code true}, if both were written. */
  public boolean storeAll(String recentRoot, String outRoot) {
    return storeAll(recentRoot, outRoot, StandardOpenOption.APPEND,
        StandardOpenOption.CREATE_NEW);
  }

  /** Stores the descriptor to all locations.
   * First attempt to store the 'out' path, if that works store to 'recent'.
   * Returns {@code true}, if both were written. */
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
   * Returns {@code true}, if the file was written. */
  public boolean storeRecent(String recentRoot, StandardOpenOption option) {
    return PersistenceUtils.storeToFileSystem(this.annotationBytes,
        this.descriptorBytes, Paths.get(recentRoot, getRecentPath()),
        option, true);
  }

  /** Stores the descriptor in out (i.e. internal storage).
   * Only writes, if the file doesn't exist yet.
   * Returns {@code true}, if the file was written. */
  public boolean storeOut(String outRoot) {
    return storeOut(outRoot, StandardOpenOption.CREATE_NEW);
  }

  /** Stores the descriptor in out (i.e. internal storage).
   * Creates, replaces, or appends according to the given option.
   * Returns {@code true}, if the file was written. */
  public boolean storeOut(String outRoot, StandardOpenOption option) {
    return PersistenceUtils.storeToFileSystem(annotationBytes,
        this.descriptorBytes, Paths.get(outRoot, getStoragePath()),
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

