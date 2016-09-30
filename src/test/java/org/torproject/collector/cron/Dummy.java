package org.torproject.collector.cron;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;

public class Dummy extends CollecTorMain {

  public Dummy(Configuration conf) {
    super(conf);
  }

  @Override
  public void startProcessing() throws ConfigurationException {
    // dummy doesn't do anything.
  }

  @Override
  public String module() {
    return "dummy";
  }
}
