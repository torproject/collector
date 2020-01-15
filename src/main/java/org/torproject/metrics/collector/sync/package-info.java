/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

/** This package coordinates syncing and merging the fetched data.
 * <p>The central class for this process is {@code SyncManager}, which
 * coordinates download from other instances and merging the new data
 * to the local directories.</p>
 * <p>Storing data to the file system is facilitated by
 * {@code SyncPersistence}.</p>
 */
package org.torproject.metrics.collector.sync;

