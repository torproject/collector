package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;

import java.util.concurrent.atomic.AtomicInteger;

public class Counter extends CollecTorMain {

  static AtomicInteger count = new AtomicInteger(0);

  public Counter(Configuration conf) {
    super(conf);
  }

  @Override
  public void startProcessing() throws ConfigurationException {
    count.getAndIncrement();
  }

  @Override
  public String module() {
    return "counter";
  }
}

