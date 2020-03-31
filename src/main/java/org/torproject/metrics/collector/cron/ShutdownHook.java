/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.cron;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Scheduler that starts the modules configured in collector.properties.
 */
public final class ShutdownHook extends Thread {

  private static final Logger logger
      = LoggerFactory.getLogger(ShutdownHook.class);

  private boolean stayAlive = true;

  /** Names the shutdown thread for debugging purposes. */
  public ShutdownHook() {
    super("CollecTor-ShutdownThread");
  }

  /**
   * Stay alive until the shutdown thread gets run.
   */
  public void stayAlive() {
    synchronized (this) {
      while (this.stayAlive) {
        try {
          this.wait();
        } catch (InterruptedException e) {
          /* Nothing we can do about this. */
        }
      }
    }
  }

  @Override
  public void run() {
    logger.info("Shutdown in progress ... ");
    Scheduler.getInstance().shutdownScheduler();
    synchronized (this) {
      this.stayAlive = false;
      this.notify();
    }
    logger.info("Shutdown finished. Exiting.");
  }
}

