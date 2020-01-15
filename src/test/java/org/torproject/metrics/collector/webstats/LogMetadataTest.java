/* Copyright 2017--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

@RunWith(Parameterized.class)
public class LogMetadataTest {

  /** Path and expected values of LogMetadata. */
  @Parameters
  public static Collection<Object[]> pathResult() {
    return Arrays.asList(new Object[][] {
        {Paths.get("in", "ph1", "vh1-error.log-20170902.xz"),
         "10001010", Boolean.FALSE,
         "Non-access logs should be discarded."},
        {Paths.get("in", "ph1", "vh1-access.log-2017.xz"),
         "10001010", Boolean.FALSE,
         "Log file should be discarded, because of wrong date format."},
        {Paths.get("in", "ph1", "vh1-access.log.xz"),
         "10001010", Boolean.FALSE,
         "Log file should be discarded, because of the missing date."},
        {Paths.get("vh1-access.log-20170901.gz"),
         "10001010", Boolean.FALSE,
         "Should be discarded because of missing physical host information."},
        {Paths.get("in", "ph1", "vh1-access.log-20170901.gz"),
         "20170901", Boolean.TRUE,
         "Should have been accepted."},
        {Paths.get("", "vh1-access.log-20170901.gz"),
         "20170901", Boolean.FALSE,
         "Should not result in metadata."},
        {Paths.get("x", "vh1-access.log-.gz"),
         "20170901", Boolean.FALSE,
         "Should not result in metadata."},
        {Paths.get("/collection/download/in/ph2", "vh2-access.log-20180901.xz"),
         "20180901", Boolean.TRUE,
         "Should have been accepted."}
    });
  }

  private Path path;
  private LocalDate date;
  private boolean valid;
  private String failureMessage;

  /** Set all test values. */
  public LogMetadataTest(Path path, String dateString, boolean valid,
      String message) {
    this.path = path;
    this.date = LocalDate.parse(dateString, DateTimeFormatter.BASIC_ISO_DATE);
    this.valid = valid;
    this.failureMessage = message;
  }

  @Test
  public void testCreate() {
    Optional<LogMetadata> element = LogMetadata.create(this.path);
    assertEquals(this.failureMessage, this.valid, element.isPresent());
    if (!this.valid) {
      return;
    }
    LogMetadata lmd = element.get();
    assertEquals(this.date, lmd.date);
    assertEquals(this.path, lmd.path);
  }

}

