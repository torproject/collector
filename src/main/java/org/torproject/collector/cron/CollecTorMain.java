/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.util.Calendar;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class CollecTorMain implements Runnable {

  private static Logger log = LoggerFactory.getLogger(CollecTorMain.class);

  protected Configuration config;

  public CollecTorMain(Configuration conf) {
    this.config = conf;
  }

  /**
   * Log errors preventing successful completion of the module.
   */
  @Override
  public final void run() {
    log.info("Starting {} module of CollecTor.", module());
    try {
      startProcessing();
    } catch (ConfigurationException | RuntimeException ce) {
      log.error("The {} module failed: {}", module(), ce.getMessage(), ce);
    }
    log.info("Terminating {} module of CollecTor.", module());
  }

  /**
   * Module specific code goes here.
   */
  protected abstract void startProcessing() throws ConfigurationException;

  /**
   * Returns the module name for logging purposes.
   */
  public abstract String module();
}

