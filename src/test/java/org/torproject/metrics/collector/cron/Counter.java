package org.torproject.metrics.collector.cron;

import org.torproject.metrics.collector.conf.Configuration;

import java.util.concurrent.atomic.AtomicInteger;

public class Counter extends CollecTorMain {

  static AtomicInteger count = new AtomicInteger(0);

  public Counter(Configuration conf) {
    super(conf);
  }

  @Override
  public void startProcessing() {
    count.getAndIncrement();
  }

  @Override
  public String module() {
    return "counter";
  }

  @Override
  protected String syncMarker() {
    return "Torperf";
  }

}

