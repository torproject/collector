/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Scheduler that starts the modules configured in collector.properties.
 */
public final class ShutdownHook extends Thread {

  private static final Logger log = LoggerFactory.getLogger(ShutdownHook.class);

  /** Names the shutdown thread for debugging purposes. */
  public ShutdownHook() {
    super("CollecTor-ShutdownThread");
  }

  @Override
  public void run() {
    log.info("Shutdown in progress ... ");
    Scheduler.getInstance().shutdownScheduler();
    log.info("Shutdown finished. Exiting.");
  }
}

