/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

/** This package coordinates syncing and merging the fetched data.
 * <p>The central class for this process is <code>SyncManager</code>, which
 * coordinates download from other instances and merging the new data
 * to the local directories.</p>
 * <p>Storing data to the file system is facilitated by
 * <code>SyncPersistence</code>.</p>
 */

