/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.indexer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collection;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Test class for {@link IndexerTask}.
 */
@RunWith(Parameterized.class)
public class IndexerTaskTest {

  @Parameterized.Parameter
  public String path;

  @Parameterized.Parameter(1)
  public Long size;

  @Parameterized.Parameter(2)
  public String lastModified;

  @Parameterized.Parameter(3)
  public String[] types;

  @Parameterized.Parameter(4)
  public String firstPublished;

  @Parameterized.Parameter(5)
  public String lastPublished;

  @Parameterized.Parameter(6)
  public String sha256;

  /**
   * Initialize test parameters.
   *
   * @return Test parameters.
   */
  @Parameterized.Parameters
  public static Collection<Object[]> pathFilename() {
    return Arrays.asList(new Object[][]{

        {"2016-09-20-13-00-00-consensus", /* Path in src/test/resources/ */
            1_618_103L, /* Size in bytes */
            "2017-09-07 12:13", /* Last-modified time */
            new String[] { "network-status-consensus-3 1.17" }, /* Types */
            "2016-09-20 13:00", /* First published */
            "2016-09-20 13:00", /* Last published */
            "3mLpDZmP/NSgOgmuPDyljxh0Lup1L6FtD16266ZCGAw="}, /* SHA-256 */

        {"2016-09-20-13-00-00-vote-49015F787433103580E3B66A1707A00E60F2D15B-"
            + "60ADC6BEC262AE921A1037D54C8A3976367DBE87",
            3_882_514L,
            "2017-09-07 12:13",
            new String[] { "network-status-vote-3 1.17" },
            "2016-09-20 13:00",
            "2016-09-20 13:00",
            "UCnSSrvdm26dJOriFgEQNQVrBLpVKbH/fF0VPRX3TGc="},

        {"2016-09-20-13-02-00",
            177_090L,
            "2017-01-13 16:55",
            new String[] { "tordnsel 1.0" },
            "2016-09-20 13:02",
            "2016-09-20 13:02",
            "4aXdw+jQ5O33AS8n+fUOwD5ZzHCICnwzvxkK8fWDhdw="},

        {"2016-10-01-16-00-00-vote-0232AF901C31A04EE9848595AF9BB7620D4C5B2E-"
            + "FEE63B4AB7CE5A6BDD09E9A5C4F01BD61EB7E4F1",
            3_226_152L,
            "2017-01-13 16:55",
            new String[] { "network-status-vote-3 1.0" },
            "2016-10-01 16:00",
            "2016-10-01 16:00",
            "bilv6zEXr0Y9f5o24RMN0lUujsJJiSQAn9LkG0XJrZE="},

        {"2016-10-02-17-00-00-consensus-microdesc",
            1_431_627L,
            "2017-09-07 12:13",
            new String[] { "network-status-microdesc-consensus-3 1.17" },
            "2016-10-02 17:00",
            "2016-10-02 17:00",
            "rrkxuLahYENLExX99Jio587/kUz9NtOoaYyKXxvX5EA="},

        {"20160920-063816-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1",
            339_256L,
            "2017-09-07 12:13",
            new String[] { "bridge-network-status 1.17" },
            "2016-09-20 06:38",
            "2016-09-20 06:38",
            "sMAcyFrZ2rxj50b6iGe3icCNMC4gBSA1y9ZH4EWTa8s="},

        {"bridge-2016-10-02-08-09-00-extra-infos",
            11_561L,
            "2017-09-07 12:13",
            new String[] { "bridge-extra-info 1.3" },
            "2016-10-02 06:09",
            "2016-10-02 06:09",
            "hat+vbyE04eH9JBQa0s6ezB6sLaStUUhvUj8CZ1aoEY="},

        {"bridge-2016-10-02-16-09-00-server-descriptors",
            5_336L,
            "2017-01-13 16:55",
            new String[] { "bridge-server-descriptor 1.2" },
            "2016-10-02 14:09",
            "2016-10-02 14:09",
            "6CtHdo+eRFOi5xBjJcOVszC1hibC5gTB+YWvn1VmIIc="},

        {"moria-1048576-2016-10-05.tpf",
            20_405L,
            "2017-09-07 12:13",
            new String[0],
            null,
            null,
            "DZyk6c0lQQ7OVZo1cmA+SuxPA+1thmuiooVifQPPOiA="},

        {"op-nl-1048576-2017-04-11.tpf",
            4_220L,
            "2017-09-20 12:14",
            new String[] { "torperf 1.1" },
            "2017-04-11 06:24",
            "2017-04-11 15:54",
            "Gwex5yN3+s2PrhekjA68XmPg+UorOfx7mUa4prd7Dt8="},

        {"relay-2016-10-02-08-05-00-extra-infos",
            20_541L,
            "2017-01-13 16:55",
            new String[] { "extra-info 1.0" },
            "2016-10-02 07:01",
            "2016-10-02 07:01",
            "3ZSO3+9ed9OwMVPx2LcVIiJfC+O30eEXEdbz64Hrp0w="},

        {"relay-2016-10-02-16-05-00-server-descriptors",
            17_404L,
            "2017-01-13 16:55",
            new String[] { "server-descriptor 1.0" },
            "2016-10-02 14:58",
            "2016-10-02 15:01",
            "uWKHHzq4+oVNdOGh0mfkLUSjwGrBlLtEtN2DtF5qcLU="},

        {"siv-1048576-2016-10-03.tpf",
            39_193L,
            "2017-01-13 16:55",
            new String[] { "torperf 1.0" },
            "2016-10-03 00:02",
            "2016-10-03 23:32",
            "paaFPI6BVuIDQ32aIuHYNCuKmBvFxsDvVCCwp+oM0GE="},

        {"torperf-51200-2016-10-02.tpf",
            233_763L,
            "2017-01-13 16:55",
            new String[] { "torperf 1.0" },
            "2016-10-02 00:00",
            "2016-10-02 23:55",
            "fqeVAXamvB4yQ/8UlZAxhJx0+1Y7IfipqIpOUqQ57rE="}
    });
  }

  /**
   * Formatter for all timestamps found in {@code index.json}.
   */
  private static DateTimeFormatter dateTimeFormatter = DateTimeFormatter
      .ofPattern("uuuu-MM-dd HH:mm").withZone(ZoneOffset.UTC);

  /**
   * Temporary folder containing all files for this test.
   */
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  /**
   * Test indexing a file.
   *
   * @throws IOException Thrown if an I/O error occurs.
   */
  @Test
  public void testIndexFile() throws IOException {
    Path indexedDirectory = this.temporaryFolder.newFolder().toPath();
    Path temporaryFile = indexedDirectory.resolve(this.path);
    try (InputStream is = getClass()
        .getClassLoader().getResourceAsStream(this.path)) {
      if (null == is) {
        fail(String.format("Unable to read test resource %s.", this.path));
        return;
      }
      Files.copy(is, temporaryFile);
    }
    Files.setLastModifiedTime(temporaryFile,
        FileTime.from(LocalDateTime.parse(this.lastModified, dateTimeFormatter)
            .toInstant(ZoneOffset.UTC)));
    assertTrue(Files.exists(temporaryFile));
    IndexerTask indexerTask = new IndexerTask(temporaryFile);
    FileNode indexResult = indexerTask.call();
    assertEquals(this.path, indexResult.path);
    assertEquals(this.size, indexResult.size);
    assertEquals(this.lastModified, indexResult.lastModified);
    SortedSet<String> expectedTypes = new TreeSet<>(Arrays.asList(this.types));
    assertEquals(expectedTypes, indexResult.types);
    assertEquals(this.firstPublished, indexResult.firstPublished);
    assertEquals(this.lastPublished, indexResult.lastPublished);
    assertEquals(this.sha256, indexResult.sha256);
  }
}

