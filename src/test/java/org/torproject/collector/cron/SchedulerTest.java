/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.cron;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.torproject.collector.MainTest;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.Key;

import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledThreadPoolExecutor;

public class SchedulerTest {

  private static final String runConfigProperties =
      "TorperfActivated=true\nTorperfPeriodMinutes=1\nTorperfOffsetMinutes=0\n"
      + "RelaydescsActivated=true\nRelaydescsPeriodMinutes=1"
      + "\nRelaydescsOffsetMinutes=0\n"
      + "ExitlistsActivated=true\nExitlistsPeriodMinutes=1\n"
      + "ExitlistsOffsetMinutes=0\n"
      + "UpdateindexActivated=true\nUpdateindexPeriodMinutes=1\n"
      + "UpdateindexOffsetMinutes=0\n"
      + "BridgedescsActivated=true\nBridgedescsPeriodMinutes=1\n"
      + "BridgedescsOffsetMinutes=0\n";

  @Test()
  public void testSimpleSchedule() throws Exception {
    Map<Key, Class<? extends CollecTorMain>> ctms = new HashMap<>();
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream(runConfigProperties.getBytes()));
    ctms.put(Key.TorperfActivated, Dummy.class);
    ctms.put(Key.BridgedescsActivated, Dummy.class);
    ctms.put(Key.RelaydescsActivated, Dummy.class);
    ctms.put(Key.ExitlistsActivated, Dummy.class);
    ctms.put(Key.UpdateindexActivated, Dummy.class);
    Field schedulerField = Scheduler.class.getDeclaredField("scheduler");
    schedulerField.setAccessible(true);
    ScheduledThreadPoolExecutor stpe = (ScheduledThreadPoolExecutor)
        schedulerField.get(Scheduler.getInstance());
    assertTrue(stpe.getQueue().isEmpty());
    Scheduler.getInstance().scheduleModuleRuns(ctms, conf);
  }

  @Test()
  public void testDelayComputation() {
    assertEquals(59_993L,
        Scheduler.computeInitialDelayMillis(7L, 60_000L, 300_000L));
    assertEquals(7L,
        Scheduler.computeInitialDelayMillis(59_993L, 60_000L, 300_000L));
    assertEquals(299_999L,
        Scheduler.computeInitialDelayMillis(60_001L, 60_000L, 300_000L));
    assertEquals(60_009L,
        Scheduler.computeInitialDelayMillis(299_991L, 60_000L, 300_000L));
  }

  @Test()
  public void testRunOnce() throws Exception {
    Map<Key, Class<? extends CollecTorMain>> ctms = new HashMap<>();
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream(("ShutdownGraceWaitMinutes=1\n"
        + runConfigProperties).getBytes()));
    conf.setProperty(Key.RunOnce.name(), "true");
    ctms.put(Key.TorperfActivated, Counter.class);
    ctms.put(Key.BridgedescsActivated, Counter.class);
    ctms.put(Key.RelaydescsActivated, Counter.class);
    ctms.put(Key.ExitlistsActivated, Counter.class);
    ctms.put(Key.UpdateindexActivated, Counter.class);
    conf.setProperty(Key.BridgeSources.name(), "Local");
    conf.setProperty(Key.RelaySources.name(), "Remote");
    conf.setProperty(Key.ExitlistSources.name(), "Remote");
    Field schedulerField = Scheduler.class.getDeclaredField("scheduler");
    schedulerField.setAccessible(true);
    ScheduledThreadPoolExecutor stpe = (ScheduledThreadPoolExecutor)
        schedulerField.get(Scheduler.getInstance());
    Scheduler.getInstance().scheduleModuleRuns(ctms, conf);
    Scheduler.getInstance().shutdownScheduler();
    assertEquals(5, Counter.count.get());
  }

  @Ignore("This test takes 180 seconds, which is too long.")
  @Test()
  public void testScheduleBrokenClass() throws Exception {
    Map<Key, Class<? extends CollecTorMain>> ctms = new HashMap<>();
    Configuration conf = new Configuration();
    conf.load(new ByteArrayInputStream(runConfigProperties.getBytes()));
    ctms.put(Key.TorperfActivated, Broken.class);
    ctms.put(Key.BridgedescsActivated, Broken.class);
    ctms.put(Key.RelaydescsActivated, Broken.class);
    ctms.put(Key.ExitlistsActivated, Broken.class);
    ctms.put(Key.UpdateindexActivated, Broken.class);
    Field schedulerField = Scheduler.class.getDeclaredField("scheduler");
    schedulerField.setAccessible(true);
    ScheduledThreadPoolExecutor stpe = (ScheduledThreadPoolExecutor)
        schedulerField.get(Scheduler.getInstance());
    Scheduler.getInstance().scheduleModuleRuns(ctms, conf);
    long sysNow = System.currentTimeMillis();
    MainTest.waitSec(180);
    assertEquals(15, Broken.count.intValue());
  }
}

