package org.torproject.metrics.collector.cron;

import org.torproject.metrics.collector.conf.Configuration;

public class Dummy extends CollecTorMain {

  public Dummy(Configuration conf) {
    super(conf);
  }

  @Override
  public void startProcessing() {
    // dummy doesn't do anything.
  }

  @Override
  public String module() {
    return "dummy";
  }

  @Override
  protected String syncMarker() {
    return "Dummy";
  }

}
