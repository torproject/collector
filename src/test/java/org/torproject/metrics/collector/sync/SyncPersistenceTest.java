/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.sync;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.Key;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@RunWith(Parameterized.class)
public class SyncPersistenceTest {

  /** All types of data that can be encountered during sync. */
  @Parameters
  public static Collection<Object[]> pathFilename() {
    return Arrays.asList(new Object[][] {

        {"exit-lists/2016-09-20-13-02-00", // expected recent path
         new String[]{"exit-lists/2016/09/20/2016-09-20-13-02-00"}, // exp. out
         "2016-09-20-13-02-00", // test-filename in src/test/resources
            1, // expected recent count of descs files
            1}, // expected output count of descs files

        {"torperf/op-nl-1048576-2017-04-11.tpf",
         new String[]{"torperf/2017/04/11/op-nl-1048576-2017-04-11.tpf"},
         "op-nl-1048576-2017-04-11.tpf",
            1,
            1},

        {"webstats/archive.torproject.org_"
             + "archeotrichon.torproject.org_access.log_20151007.xz",
         new String[]{"webstats/archive.torproject.org/2015/10/07/"
             + "archive.torproject.org_archeotrichon.torproject.org"
             + "_access.log_20151007.xz"},
         "archeotrichon.torproject.org/archive.torproject.org_"
             + "archeotrichon.torproject.org_access.log_20151007.xz",
            1,
            1},

        {"webstats/metrics.torproject.org_"
             + "meronense.torproject.org_access.log_20170531.xz",
         new String[]{"webstats/metrics.torproject.org/2017/05/31/"
             + "metrics.torproject.org_meronense.torproject.org"
             + "_access.log_20170531.xz"},
         "meronense.torproject.org/metrics.torproject.org_"
             + "meronense.torproject.org_access.log_20170531.gz",
            1,
            1},

        {"relay-descriptors/server-descriptors/"
             + "2016-10-05-19-06-17-server-descriptors",
         new String[]{"relay-descriptors/server-descriptor/2016/10/e/3/"
             + "e381ce74a1a592f6d375706665aba6d4d22923f1",
             "relay-descriptors/server-descriptor/2016/10/e/1/"
             + "e1142337dee5b890393a0891acbde51577c2b743",
             "relay-descriptors/server-descriptor/2016/10/5/b/"
             + "5b202650802a916f1ec3a1ef36b98706e3747701",
             "relay-descriptors/server-descriptor/2016/10/5/a/"
             + "5a536243bf056cd7177ddfd8eb363fec978f3343",
             "relay-descriptors/server-descriptor/2016/10/4/1/"
             + "4179c50d3c764bc85c9d719e14e55a6cc232a10d",
             "relay-descriptors/server-descriptor/2016/10/2/0/"
             + "2091f76a8256e479cbe4f57be85f87909af07236",
             "relay-descriptors/server-descriptor/2016/10/c/8/"
             + "c8c3588019f7c896eb4185cfc1074cfe5eb405ea",
             "relay-descriptors/server-descriptor/2016/10/b/b/"
             + "bbca7ed70ba6ea88f995b067a004f5a4d0903d6e",
             "relay-descriptors/server-descriptor/2016/10/d/a/"
             + "dae8966ca600b46bc75ed5efb97286481e9a6876",
             "relay-descriptors/server-descriptor/2016/10/a/0/"
             + "a0ed9227a9413f140445002ce412f8828591e7ec"},
         "relay-2016-10-02-16-05-00-server-descriptors",
            1,
            10},

        {"relay-descriptors/consensuses/2016-09-20-13-00-00-consensus",
         new String[]{"relay-descriptors/consensus/2016/09/20/"
             + "2016-09-20-13-00-00-consensus"},
         "2016-09-20-13-00-00-consensus",
            1,
            1},

        {"relay-descriptors/microdescs/consensus-microdesc/"
             + "2016-10-02-17-00-00-consensus-microdesc",
         new String[]{"relay-descriptors/microdesc/2016/10/consensus-microdesc/"
             + "02/2016-10-02-17-00-00-consensus-microdesc"},
         "2016-10-02-17-00-00-consensus-microdesc",
            1,
            1},

        {"relay-descriptors/votes/2016-10-01-16-00-00-vote"
             + "-0232AF901C31A04EE9848595AF9BB7620D4C5B2E"
             + "-FEE63B4AB7CE5A6BDD09E9A5C4F01BD61EB7E4F1",
         new String[]{"relay-descriptors/vote/2016/10/01/"
             + "2016-10-01-16-00-00-vote"
             + "-0232AF901C31A04EE9848595AF9BB7620D4C5B2E"
             + "-FEE63B4AB7CE5A6BDD09E9A5C4F01BD61EB7E4F1"},
         "2016-10-01-16-00-00-vote-0232AF901C31A04EE9848595AF9BB7620D4C5B2E-"
             + "FEE63B4AB7CE5A6BDD09E9A5C4F01BD61EB7E4F1",
            1,
            1},

        {"relay-descriptors/votes/2016-09-20-13-00-00-vote-"
             + "49015F787433103580E3B66A1707A00E60F2D15B"
             + "-60ADC6BEC262AE921A1037D54C8A3976367DBE87",
         new String[]{"relay-descriptors/vote/2016/09/20/"
             + "2016-09-20-13-00-00-vote-"
             + "49015F787433103580E3B66A1707A00E60F2D15B"
             + "-60ADC6BEC262AE921A1037D54C8A3976367DBE87"},
         "2016-09-20-13-00-00-vote-49015F787433103580E3B66A1707A00E60F2D15B"
             + "-60ADC6BEC262AE921A1037D54C8A3976367DBE87",
            1,
            1},

        {"relay-descriptors/extra-infos/2016-10-05-19-06-17-extra-infos",
         new String[]{"relay-descriptors/extra-info/2016/10/9/a/"
             + "9a4b819baeeeb6952ba737b752471b8637e75a5c",
             "relay-descriptors/extra-info/2016/10/6/a/"
             + "6a36d4ac36447e645c91ed63633a09197b7ad97e",
             "relay-descriptors/extra-info/2016/10/e/b/"
             + "eb73b59951bc1b0403be81220fb75be464954c31",
             "relay-descriptors/extra-info/2016/10/4/e/"
             + "4ef90738e54a403b265120dcbab7b494e0c68d3b",
             "relay-descriptors/extra-info/2016/10/c/a/"
             + "ca86eb96d22d188bb574b6b329ab21e0d9243516",
             "relay-descriptors/extra-info/2016/10/8/2/"
             + "82471deac7b251089a0878d29a228d4e323b823f",
             "relay-descriptors/extra-info/2016/10/3/6/"
             + "36691feb7cec6a9630b9ecd11a9b5dc61c147c5d",
             "relay-descriptors/extra-info/2016/10/3/1/"
             + "317586098443ed19b200417556a08ebc42133521",
             "relay-descriptors/extra-info/2016/10/0/4/"
             + "04219ada0be922fa7518d36b0d8e66afc55e8603"},
        "relay-2016-10-02-08-05-00-extra-infos",
            1,
            9},

        {"bridge-descriptors/extra-infos/2016-10-05-19-06-17-extra-infos",
         new String[]{"bridge-descriptors/2016/10/extra-infos/9/f/"
             + "9f88a7c2abe6665d204137ba8c2661d42e7c2829",
             "bridge-descriptors/2016/10/extra-infos/e/e/"
             + "eee0dc51b9a0a71ba73610123b13cea212b5cf83",
             "bridge-descriptors/2016/10/extra-infos/e/1/"
             + "e11c5239494bad2f6f3759f1104a2f6182beab4d",
             "bridge-descriptors/2016/10/extra-infos/c/a/"
             + "cab78ea0ffe9a7bc00527fef19f546c47d59f01a",
             "bridge-descriptors/2016/10/extra-infos/3/4/"
             + "3412a1dccd183a1c0bd1b748f34d88594be6ea52",
             "bridge-descriptors/2016/10/extra-infos/3/1/"
             + "31bcea576e77ba66150f7903b588c919adad849c",
             "bridge-descriptors/2016/10/extra-infos/b/c/"
             + "bcfcbb38b15e9b500b1a6e9b0bcbbce858660f17",
             "bridge-descriptors/2016/10/extra-infos/7/a/"
             + "7a93ca1edc543e747f1157bc3a557890335311a4",
             "bridge-descriptors/2016/10/extra-infos/1/6/"
             + "16d2b79fbd0a8567c6afd7585c775ac7745561e3",
             "bridge-descriptors/2016/10/extra-infos/f/a/"
             + "fabd8f614633ec2d2d405f2554e14381bc33d9cb"},
         "bridge-2016-10-02-08-09-00-extra-infos",
            1,
            10},

        {"bridge-descriptors/server-descriptors/"
             + "2016-10-05-19-06-17-server-descriptors",
         new String[]{"bridge-descriptors/2016/10/server-descriptors"
             + "/6/1/614414898ee133ee9bf6b10a9898cab518c5453e",
             "bridge-descriptors/2016/10/server-descriptors/e/5/"
             + "e5d46e88cb52d4fc0524398cfb7a6754394bc5e9",
             "bridge-descriptors/2016/10/server-descriptors/5/b/"
             + "5b20316b03afc98a165a219044b6fa6ca34c58ab",
             "bridge-descriptors/2016/10/server-descriptors/c/3/"
             + "c32acc52826b37e5319f1bac2f8812b33a772540",
             "bridge-descriptors/2016/10/server-descriptors/7/8/"
             + "784d6f9e82426072fbfc7a42f8f7133ba6ec1453",
             "bridge-descriptors/2016/10/server-descriptors/a/8/"
             + "a8a5509ad1393c8f36abd2d8f0de1bb751926872",
             "bridge-descriptors/2016/10/server-descriptors/0/7/"
             + "07d952e9020cb68a63d9156653a2e41af4af4d44",
             "bridge-descriptors/2016/10/server-descriptors/0/a/"
             + "0a65c636a20631bd5deb2f10dc664d2032303c46"},
         "bridge-2016-10-02-16-09-00-server-descriptors",
            1,
            8},

        {"bridge-descriptors/statuses/"
             + "20160920-063816-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1",
         new String[]{"bridge-descriptors/2016/09/statuses/20/"
             + "20160920-063816-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1"},
         "20160920-063816-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1",
            1,
            1}
    });
  }

  private String expectedRecentDir;
  private String[] expectedOutputDir;
  private int outCount;
  private int recentCount;
  private String filename;
  private File fileForName;
  private File recent;
  private File output;
  private String recentName;
  private String outputName;
  private Configuration conf = new Configuration();

  /** This constructor receives the above defined data for each run. */
  public SyncPersistenceTest(String subRecent, String[] subOutput, String fn,
      int recentCount, int outCount) {
    this.expectedRecentDir = subRecent;
    this.expectedOutputDir = subOutput;
    this.filename = fn;
    this.fileForName = new File(fn);
    this.outCount = outCount;
    this.recentCount = recentCount;
  }

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test()
  public void testDescWriteRecent() throws Exception {
    makeTemporaryFolders();
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    SyncPersistence persist = new SyncPersistence(conf);
    persist.storeDescs(dp.parseDescriptors(bytesFromResource(),
        fileForName, filename), 1475694377000L);
    persist.cleanDirectory();
    List<File> recentList = new ArrayList<>();
    Files.walkFileTree(recent.toPath(), new FileCollector(recentList));
    String dataUsed = "data used: " + expectedRecentDir + ", " + filename
        + ", resulting list: ";
    assertEquals(dataUsed + recentList, recentCount, recentList.size());
    assertEquals(dataUsed + recentList,
        recent.toString() + "/" + expectedRecentDir,
        recentList.get(0).toString());
  }

  @Test()
  public void testDescWriteOutput() throws Exception {
    makeTemporaryFolders();
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    SyncPersistence persist = new SyncPersistence(conf);
    persist.storeDescs(dp.parseDescriptors(bytesFromResource(),
        fileForName, filename), 1475694377000L);
    persist.cleanDirectory();
    List<File> recentList = new ArrayList<>();
    List<File> outputList = new ArrayList<>();
    Files.walkFileTree(output.toPath(), new FileCollector(outputList));
    String dataUsed = "data used: " + expectedOutputDir[0] + ", " + filename
        + ", resulting list: ";
    assertEquals(dataUsed + outputList, outCount, outputList.size());
    for (String exp : expectedOutputDir) {
      File expFile = new File(output.toString(), exp);
      assertTrue(dataUsed + outputList + "\nfollowing file missing:" + expFile,
          outputList.remove(expFile));
    }
    assertTrue("output list should be empty now, but " + outputList,
        outputList.isEmpty());
  }

  @Test()
  public void testRecentFileContent() throws Exception {
    if (this.filename.contains(".log")) {
      return; // Skip this test, because logs are compressed and sanitized.
    }
    conf = new Configuration();
    makeTemporaryFolders();
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    SyncPersistence persist = new SyncPersistence(conf);
    persist.storeDescs(dp.parseDescriptors(bytesFromResource(),
        fileForName, filename), 1475694377000L);
    persist.cleanDirectory();
    List<File> recentList = new ArrayList<>();
    Files.walkFileTree(recent.toPath(), new FileCollector(recentList));
    assertEquals(recentCount, recentList.size());
    List<String> content = Files.readAllLines(recentList.get(0).toPath(),
        StandardCharsets.UTF_8);
    List<String> expContent = linesFromResource(filename);
    int contentSize = content.size();
    assertEquals("Number of lines incorrect for file '" + filename + "': "
        + content, expContent.size(), contentSize);
    for (String line : expContent) {
      assertTrue("Couln't remove " + line + " from " + recentList.get(0),
          content.remove(line));
      assertEquals(--contentSize, content.size());
    }
    assertTrue("Lines left over: " + content, content.isEmpty());
  }

  @Test()
  public void testOutFileContent() throws Exception {
    if (this.filename.contains(".log")) {
      return; // Skip this test, because logs are compressed and sanitized.
    }
    conf = new Configuration();
    makeTemporaryFolders();
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    SyncPersistence persist = new SyncPersistence(conf);
    persist.storeDescs(dp.parseDescriptors(bytesFromResource(),
        fileForName, filename), 1475694377000L);
    persist.cleanDirectory();
    List<File> outputList = new ArrayList<>();
    Files.walkFileTree(output.toPath(), new FileCollector(outputList));
    assertEquals(outCount, outputList.size());
    List<String> expContent = linesFromResource(filename);
    int expContentSize = expContent.size();
    for (File file : outputList) {
      for (String line : Files.readAllLines(file.toPath(),
          StandardCharsets.UTF_8)) {
        assertTrue("Couldn't remove " + line + ".", expContent.remove(line));
        assertEquals(--expContentSize, expContent.size());
      }
    }
    assertTrue("Lines left over: " + expContent, expContent.isEmpty());
  }

  private void makeTemporaryFolders() throws Exception {
    recent = tmpf.newFolder("recent");
    output = tmpf.newFolder("out");
    recentName = recent.toString();
    outputName = output.toString();
    conf.setProperty(Key.RecentPath.name(), recentName);
    conf.setProperty(Key.OutputPath.name(), outputName);
  }

  private byte[] bytesFromResource() throws Exception {
    return Files.readAllBytes((new File(getClass()
        .getClassLoader().getResource(filename).toURI())).toPath());
  }

  private String stringFromResource() {
    BufferedReader br = new BufferedReader(new InputStreamReader(getClass()
        .getClassLoader().getResourceAsStream(filename)));
    return br.lines().collect(Collectors.joining("\n", "", "\n"));
  }

  private String stringFromFile(File file) throws Exception {
    return Files.lines(file.toPath(), StandardCharsets.UTF_8)
        .collect(Collectors.joining("\n", "", "\n"));
  }

  private List<String> linesFromResource(String filename) {
    BufferedReader br = new BufferedReader(new InputStreamReader(getClass()
        .getClassLoader().getResourceAsStream(filename)));
    return br.lines().collect(Collectors.toList());
  }

}
