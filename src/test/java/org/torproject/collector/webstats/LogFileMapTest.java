/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.webstats;

import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Paths;
import java.util.Optional;

public class LogFileMapTest {

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test
  public void makeLogFileMap() throws Exception {
    LogFileMap lfm = new LogFileMap(tmpf.newFolder().toPath());
    for (String path : new String[] {"in/ph1/vh1-access.log-20170901.gz",
        "in/ph1/vh1-access.log-20170902.xz"}) {
      Optional<LogMetadata> element
          = LogMetadata.create(Paths.get(path));
      assertTrue(element.isPresent());
      lfm.add(element.get());
    }
  }

}

