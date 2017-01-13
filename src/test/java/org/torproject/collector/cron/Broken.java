/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;

import java.util.concurrent.atomic.AtomicInteger;

public class Broken extends CollecTorMain {

  static AtomicInteger count = new AtomicInteger(0);

  public Broken(Configuration conf) {
    super(conf);
  }

  @Override
  public void startProcessing() throws ConfigurationException {
    count.getAndIncrement();
    try {
      Thread.sleep(10);
    } catch (Exception e) { /* ignored */ }
    if (count.get() % 2 == 0) {
      throw new Error("Throwing an Error.");
    } else {
      throw new RuntimeException("Throwing an Exception.");
    }
  }

  @Override
  public String module() {
    return "broken";
  }

  @Override
  protected String syncMarker() {
    return "Broken";
  }

}

