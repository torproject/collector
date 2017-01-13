/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.torproject.collector.Main;
import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Tests the bridge descriptor sanitizer by preparing a temporary folder
 * with non-sanitized bridge descriptors, running the sanitizer, and
 * verifying the sanitized descriptors. */
public class SanitizedBridgesWriterTest {

  /** Temporary folder containing all files for this test. */
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  /** Directory containing bridge descriptor tarballs to sanitize. */
  private String bridgeDirectoriesDir;

  /** Directory holding recent descriptor files served by CollecTor. */
  private File recentDirectory;

  /** Directory storing all intermediate state that needs to be preserved
   * between processing runs. */
  private String statsDirectory;

  /** Directory holding sanitized bridge descriptor files. */
  private Path sanitizedBridgesDirectory;

  /** CollecTor configuration for this test. */
  private Configuration configuration;

  /** Server descriptor builder used to build the first and only server
   * descriptor for this test, unless removed from the tarball builder.*/
  private DescriptorBuilder defaultServerDescriptorBuilder;

  /** Extra-info descriptor builder used to build the first and only
   * extra-info descriptor for this test, unless removed from the tarball
   * builder.*/
  private DescriptorBuilder defaultExtraInfoDescriptorBuilder;

  /** Network status builder used to build the first and only network
   * status for this test, unless removed from the tarball builder.*/
  private DescriptorBuilder defaultNetworkStatusBuilder;

  /** Tarball builder to build the first and only tarball, unless removed
   * from the test. */
  private TarballBuilder defaultTarballBuilder;

  /** Tarball builder(s) for this test. */
  private List<TarballBuilder> tarballBuilders;

  /** Parsed sanitized bridge descriptors with keys being file names and
   * values being sanitized descriptor lines. */
  private Map<String, List<String>> parsedFiles;

  /** Parsed sanitized default server descriptor. */
  private List<List<String>> parsedServerDescriptors;

  /** Parsed sanitized default extra-info descriptor. */
  private List<List<String>> parsedExtraInfoDescriptors;

  /** Parsed sanitized default network status. */
  private List<List<String>> parsedNetworkStatuses;

  /** Prepares the temporary folder and the various builders for this
   * test. */
  @Before
  public void createTemporaryFolderAndBuilders()
      throws IOException {
    this.bridgeDirectoriesDir = this.temporaryFolder.newFolder("in").toString();
    this.recentDirectory = this.temporaryFolder.newFolder("recent");
    this.statsDirectory = this.temporaryFolder.newFolder("stats").toString();
    this.sanitizedBridgesDirectory =
        this.temporaryFolder.newFolder("out", "bridge-descriptors").toPath();
    this.initializeTestConfiguration();
    this.defaultServerDescriptorBuilder = new ServerDescriptorBuilder();
    this.defaultExtraInfoDescriptorBuilder = new ExtraInfoDescriptorBuilder();
    this.defaultNetworkStatusBuilder = new NetworkStatusBuilder();
    this.defaultTarballBuilder = new TarballBuilder(
        "from-tonga-2016-07-01T000702Z.tar.gz", 1467331624000L);
    this.defaultTarballBuilder.add("bridge-descriptors", 1467331622000L,
        Arrays.asList(new DescriptorBuilder[] {
            this.defaultServerDescriptorBuilder }));
    this.defaultTarballBuilder.add("cached-extrainfo", 1467327972000L,
        Arrays.asList(new DescriptorBuilder[] {
            this.defaultExtraInfoDescriptorBuilder }));
    this.defaultTarballBuilder.add("cached-extrainfo.new", 1467331623000L,
        Arrays.asList(new DescriptorBuilder[] { }));
    this.defaultTarballBuilder.add("networkstatus-bridges",
        1467330028000L, Arrays.asList(new DescriptorBuilder[] {
            this.defaultNetworkStatusBuilder }));
    this.tarballBuilders = new ArrayList<>(
        Arrays.asList(this.defaultTarballBuilder));
  }

  /** Initializes a configuration for the bridge descriptor sanitizer. */
  private void initializeTestConfiguration() throws IOException {
    this.configuration = new Configuration();
    this.configuration.load(getClass().getClassLoader().getResourceAsStream(
        Main.CONF_FILE));
    this.configuration.setProperty(Key.BridgedescsActivated.name(), "true");
    this.configuration.setProperty(Key.RecentPath.name(),
        recentDirectory.getAbsolutePath());
    this.configuration.setProperty(Key.StatsPath.name(), statsDirectory);
    this.configuration.setProperty(Key.BridgeLocalOrigins.name(),
        bridgeDirectoriesDir);
    this.configuration.setProperty(Key.OutputPath.name(),
        sanitizedBridgesDirectory.toFile().getParent().toString());
  }

  /** Runs this test by executing all builders, performing the sanitizing
   * process, and parsing sanitized bridge descriptors for inspection. */
  private void runTest() throws IOException, ConfigurationException {
    for (TarballBuilder tarballBuilder : this.tarballBuilders) {
      tarballBuilder.build(new File(this.bridgeDirectoriesDir));
    }
    SanitizedBridgesWriter sbw = new SanitizedBridgesWriter(configuration);
    sbw.startProcessing();
    this.parsedFiles = new LinkedHashMap<>();
    this.parsedServerDescriptors = new ArrayList<>();
    this.parsedExtraInfoDescriptors = new ArrayList<>();
    this.parsedNetworkStatuses = new ArrayList<>();
    Files.walkFileTree(sanitizedBridgesDirectory,
        new SimpleFileVisitor<Path>() {
          @Override
          public FileVisitResult visitFile(Path path, BasicFileAttributes bfa)
              throws IOException {
            List<String> parsedLines = Files.readAllLines(path,
                StandardCharsets.UTF_8);
            if (parsedLines.get(0).startsWith(
                "@type bridge-server-descriptor ")) {
              parsedServerDescriptors.add(parsedLines);
            } else if (parsedLines.get(0).startsWith(
                "@type bridge-extra-info ")) {
              parsedExtraInfoDescriptors.add(parsedLines);
            } else if (parsedLines.get(0).startsWith(
                "@type bridge-network-status ")) {
              parsedNetworkStatuses.add(parsedLines);
            }
            parsedFiles.put(sanitizedBridgesDirectory.relativize(path)
                .toString(), parsedLines);
            return FileVisitResult.CONTINUE;
          }
        });
  }

  @Test
  public void testServerDescriptorDefault() throws Exception {
    this.runTest();
    List<String> expectedLines = Arrays.asList(
        "@type bridge-server-descriptor 1.2",
        "router MeekGoogle 127.0.0.1 1 0 0",
        "master-key-ed25519 3HC9xnykNIfNdFDuJWwxaJSM5GCaIJKUtAYgMixbsOM",
        "platform Tor 0.2.7.6 on Linux",
        "protocols Link 1 2 Circuit 1",
        "published 2016-06-30 21:43:52",
        "fingerprint 88F7 4584 0F47 CE0C 6A4F E61D 8279 50B0 6F9E 4534",
        "uptime 543754",
        "bandwidth 3040870 5242880 56583",
        "extra-info-digest B026CF0F81712D94BBF1362294882688DF247887 "
            + "/XWPeILeik+uTGaKL3pnUeQfYS87SfjKVkwTiCmbqi0",
        "hidden-service-dir",
        "contact somebody",
        "ntor-onion-key YjZG5eaQ1gmXvlSMGEBwM7OLswv8AtXZr6ccOnDUKQw=",
        "reject *:*",
        "router-digest-sha256 "
            + "KI4PRYH9rDCDLYPNv9NF53gFy8pJjIpeJ7UkzIGOAnw",
        "router-digest B6922FF5C045814DF4BCB72A0D6C9417CFFBD80A");
    assertEquals("Sanitized descriptor does not contain expected lines.",
        expectedLines, this.parsedServerDescriptors.get(0));
    assertTrue("Sanitized descriptor file name differs.",
        this.parsedFiles.containsKey("2016/06/server-descriptors/b/6/"
        + "b6922ff5c045814df4bcb72a0d6c9417cffbd80a"));
  }

  @Test
  public void testServerDescriptorEmpty() throws Exception {
    this.defaultServerDescriptorBuilder.clear();
    this.runTest();
    assertTrue("No server descriptor provided as input.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorOnlyAnnotation() throws Exception {
    this.defaultServerDescriptorBuilder.removeAllExcept("@purpose bridge");
    this.runTest();
  }

  @Test
  public void testServerDescriptorAdditionalAnnotation()
      throws Exception {
    this.defaultServerDescriptorBuilder.insertBeforeLineStartingWith(
        "@purpose bridge", Arrays.asList("@source 198.50.200.131"));
    this.runTest();
    assertEquals("Expected 3 sanitized descriptors.", 3,
        this.parsedFiles.size());
  }

  @Test
  public void testServerDescriptorHashedIpAndTcp() throws Exception {
    this.configuration.setProperty(Key.ReplaceIpAddressesWithHashes.name(),
        "true");
    this.configuration.setProperty(Key.BridgeDescriptorMappingsLimit.name(),
        "30000");
    this.defaultServerDescriptorBuilder.insertBeforeLineStartingWith(
        "platform ", Arrays.asList("or-address [2:5:2:5:2:5:2:5]:25"));
    Path bridgeIpSecretsFile = Paths.get(statsDirectory, "bridge-ip-secrets");
    BufferedWriter writer = Files.newBufferedWriter(bridgeIpSecretsFile,
        StandardCharsets.UTF_8);
    writer.write("2016-06,8ad0d1410d64256bdaa3977427f6db012c5809082a464c658d651"
        + "304e25654902ed0df551c8eed19913ab7aaf6243cb3adc0f4a4b93ee77991b8c572e"
        + "a25ca2ea5cd311dabe2f8b72243837ec88bcb0c758657\n");
    writer.close();
    this.runTest();
    assertFalse("Server descriptor not sanitized.",
        this.parsedServerDescriptors.isEmpty());
    assertTrue("IPv4 address and/or TCP port not sanitized as expected.",
        this.parsedServerDescriptors.get(0).contains(
        "router MeekGoogle 10.51.223.72 56172 0 0"));
    assertTrue("IPv6 address and/or TCP port not sanitized as expected.",
        this.parsedServerDescriptors.get(0).contains(
        "or-address [fd9f:2e19:3bcf::0c:b8a6]:59690"));
  }

  @Test
  public void testServerDescriptorRouterLineTruncated() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith("router ",
        Arrays.asList("router MeekGoogle"));
    this.runTest();
    assertTrue("Sanitized server descriptor with invalid router line.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorProtoLine() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith("protocols ",
        Arrays.asList("proto Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 "
        + "HSRend=1-2 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2"));
    this.runTest();
    assertFalse("Sanitized server descriptor with valid proto line.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorFingerprintTruncated() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "fingerprint ", Arrays.asList("fingerprint 4"));
    this.runTest();
    assertTrue("Sanitized server descriptor with invalid fingerprint "
        + "line.", this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorFingerprintInvalidHex()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "fingerprint ", Arrays.asList("fingerprint FUN!"));
    this.runTest();
    assertTrue("Sanitized server descriptor with invalid fingerprint "
        + "line.", this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorFingerprintOpt() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith("fingerprint ",
        Arrays.asList("opt fingerprint 46D4 A711 97B8 FA51 5A82 6C6B 017C 522F "
        + "E264 655B"));
    this.runTest();
    this.parsedServerDescriptors.get(0).contains("opt fingerprint 88F7 "
        + "4584 0F47 CE0C 6A4F E61D 8279 50B0 6F9E 4534");
  }

  @Test
  public void testServerDescriptorExtraInfoDigestInvalidHex()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "extra-info-digest ", Arrays.asList("extra-info-digest 6"));
    this.runTest();
    assertTrue("Sanitized server descriptor with invalid extra-info "
        + "line.", this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorExtraInfoDigestInvalidBase64()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "extra-info-digest ", Arrays.asList("extra-info-digest "
        + "6D03E80568DEFA102968D144CB35FFA6E3355B8A "
        + "#*?$%x@nxukmmcT1+UnDg4qh0yKbjVUYKhGL8VksoJA"));
    this.runTest();
    assertTrue("Invalid base64 in server descriptor accepted.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorExtraInfoDigestSha1Only()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "extra-info-digest ", Arrays.asList("extra-info-digest "
        + "6D03E80568DEFA102968D144CB35FFA6E3355B8A"));
    this.runTest();
    assertTrue("Expected different extra-info-digest line.",
        this.parsedServerDescriptors.get(0).contains(
        "extra-info-digest B026CF0F81712D94BBF1362294882688DF247887"));
  }

  @Test
  public void testServerDescriptorExtraInfoDigestThirdArgument()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "extra-info-digest ", Arrays.asList("extra-info-digest "
        + "6D03E80568DEFA102968D144CB35FFA6E3355B8A "
        + "cy/LwP7nxukmmcT1+UnDg4qh0yKbjVUYKhGL8VksoJA 00"));
    this.runTest();
    assertTrue("Third argument to extra-info-digest line should not be "
        + "dropped silently.", this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorExtraInfoDigestOpt() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "extra-info-digest ", Arrays.asList("opt extra-info-digest "
        + "6D03E80568DEFA102968D144CB35FFA6E3355B8A "
        + "cy/LwP7nxukmmcT1+UnDg4qh0yKbjVUYKhGL8VksoJA"));
    this.runTest();
    this.parsedServerDescriptors.get(0).contains("opt extra-info-digest "
        + "B026CF0F81712D94BBF1362294882688DF247887 "
        + "/XWPeILeik+uTGaKL3pnUeQfYS87SfjKVkwTiCmbqi0");
  }

  @Test
  public void testServerDescriptorRejectOwnAddress() throws Exception {
    this.defaultServerDescriptorBuilder.insertBeforeLineStartingWith(
        "reject *:*", Arrays.asList("reject 198.50.200.131:*", "accept *:80"));
    this.runTest();
    List<String> parsedLines = this.parsedServerDescriptors.get(0);
    for (int i = 0; i < parsedLines.size(); i++) {
      if ("reject 127.0.0.1:*".equals(parsedLines.get(i))) {
        assertEquals("accept line out of order.", "accept *:80",
            parsedLines.get(i + 1));
        assertEquals("reject line out of order.", "reject *:*",
            parsedLines.get(i + 2));
        return;
      }
    }
    fail("IP address in reject line should have been replaced: "
        + parsedLines);
  }

  @Test
  public void testServerDescriptorEd25519IdentityMasterKeyMismatch()
      throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "master-key-ed25519 ", Arrays.asList("master-key-ed25519 "
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    this.runTest();
    assertTrue("Mismatch between Ed25519 identity and master key.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorEd25519IdentityA() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "identity-ed25519", Arrays.asList("identity-ed25519",
        "-----BEGIN ED25519 CERT-----",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "-----END ED25519 CERT-----"));
    this.runTest();
    assertTrue("Ed25519 identity all A's conflicts with master key?",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorEd25519IdentityEToF() throws Exception {
    String change9sTo6s =
        "ZEXE7RkiEJ1l5Ij9hc9TJOpM7/9XSPZnF/PbMfE0u3n3JbOO3s82GN6BPuA0v2Cs";
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(change9sTo6s,
        Arrays.asList(change9sTo6s.replaceAll("9", "6")));
    this.runTest();
    assertTrue("Mismatch between identity and master key.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorEd25519IdentitySlash() throws Exception {
    this.defaultServerDescriptorBuilder.replaceLineStartingWith(
        "identity-ed25519", Arrays.asList("identity-ed25519",
        "-----BEGIN ED25519 CERT-----",
        "////////////////////////////////////////////////////////////////",
        "////////////////////////////////////////////////////////////////",
        "///////////////////////////////////////////////////////////=",
        "-----END ED25519 CERT-----"));
    this.runTest();
    assertTrue("Ed25519 identity all slashes conflicts with master key.",
        this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testServerDescriptorFamilyInvalidFingerprint()
      throws Exception {
    this.defaultServerDescriptorBuilder.insertBeforeLineStartingWith(
        "hidden-service-dir", Arrays.asList("family $0"));
    this.runTest();
    assertTrue("Sanitized server descriptor with invalid fingerprint in "
        + "family line.", this.parsedServerDescriptors.isEmpty());
  }

  @Test
  public void testExtraInfoDescriptorDefault() throws Exception {
    this.runTest();
    List<String> expectedLines = Arrays.asList(
        "@type bridge-extra-info 1.3",
        "extra-info MeekGoogle 88F745840F47CE0C6A4FE61D827950B06F9E4534",
        "master-key-ed25519 3HC9xnykNIfNdFDuJWwxaJSM5GCaIJKUtAYgMixbsOM",
        "published 2016-06-30 21:43:52",
        "write-history 2016-06-30 18:40:48 (14400 s) "
            + "415744,497664,359424,410624,420864,933888",
        "read-history 2016-06-30 18:40:48 (14400 s) "
            + "4789248,6237184,4473856,5039104,5567488,5440512",
        "geoip-db-digest 6346E26E2BC96F8511588CE2695E9B0339A75D32",
        "geoip6-db-digest 43CCB43DBC653D8CC16396A882C5F116A6004F0C",
        "dirreq-stats-end 2016-06-30 14:40:48 (86400 s)",
        "dirreq-v3-ips ",
        "dirreq-v3-reqs ",
        "dirreq-v3-resp ok=0,not-enough-sigs=0,unavailable=0,not-found=0,"
            + "not-modified=0,busy=0",
        "dirreq-v3-direct-dl complete=0,timeout=0,running=0",
        "dirreq-v3-tunneled-dl complete=0,timeout=0,running=0",
        "transport meek",
        "transport meek",
        "bridge-stats-end 2016-06-30 14:41:18 (86400 s)",
        "bridge-ips ",
        "bridge-ip-versions v4=0,v6=0",
        "bridge-ip-transports ",
        "router-digest-sha256 "
            + "/XWPeILeik+uTGaKL3pnUeQfYS87SfjKVkwTiCmbqi0",
        "router-digest B026CF0F81712D94BBF1362294882688DF247887");
    assertEquals("Sanitized descriptor does not contain expected lines.",
        expectedLines, this.parsedExtraInfoDescriptors.get(0));
    assertTrue("Sanitized descriptor file name differs. " + this.parsedFiles,
        this.parsedFiles.containsKey("2016/06/extra-infos/b/0/"
        + "b026cf0f81712d94bbf1362294882688df247887"));
  }

  @Test
  public void testExtraInfoDescriptorExtraInfoLineTruncated()
      throws Exception {
    this.defaultExtraInfoDescriptorBuilder.replaceLineStartingWith(
        "extra-info ", Arrays.asList("extra-info "));
    this.runTest();
  }

  @Test
  public void testExtraInfoDescriptorExtraInfoInvalidHex()
      throws Exception {
    this.defaultExtraInfoDescriptorBuilder.replaceLineStartingWith(
        "extra-info ", Arrays.asList("extra-info MeekGoogle 4"));
    this.runTest();
    assertTrue("Sanitized extra-info descriptor with invalid extra-info "
        + "line.", this.parsedExtraInfoDescriptors.isEmpty());
  }

  @Test
  public void testExtraInfoDescriptorTransportSpace() throws Exception {
    this.defaultExtraInfoDescriptorBuilder.replaceLineStartingWith(
        "transport ", Arrays.asList("transport "));
    this.runTest();
    assertTrue("Sanitized extra-info descriptor with invalid transport "
        + "line.", this.parsedExtraInfoDescriptors.isEmpty());
  }

  @Test
  public void testExtraInfoDescriptorTransportInfoRemoved() throws Exception {
    this.defaultExtraInfoDescriptorBuilder.insertBeforeLineStartingWith(
        "bridge-stats-end ", Arrays.asList("transport-info secretkey"));
    this.runTest();
    for (String line : this.parsedExtraInfoDescriptors.get(0)) {
      assertFalse("transport-info line should not have been retained.",
          line.startsWith("transport-info "));
    }
  }

  @Test
  public void testExtraInfoDescriptorHidservRetained() throws Exception {
    this.defaultExtraInfoDescriptorBuilder.insertBeforeLineStartingWith(
        "transport ",
        Arrays.asList("hidserv-stats-end 2016-11-23 14:48:05 (86400 s)",
        "hidserv-rend-relayed-cells 27653088 delta_f=2048 epsilon=0.30 "
        + "bin_size=1024",
        "hidserv-dir-onions-seen 204 delta_f=8 epsilon=0.30 bin_size=8"));
    this.runTest();
    int foundHidservLines = 0;
    if (!this.parsedExtraInfoDescriptors.isEmpty()) {
      for (String line : this.parsedExtraInfoDescriptors.get(0)) {
        if (line.startsWith("hidserv-")) {
          foundHidservLines++;
        }
      }
    }
    assertEquals("3 hidserv-* lines should have been retained.", 3,
        foundHidservLines);
  }

  @Test
  public void testExtraInfoDescriptorRouterSignatureLineSpace()
      throws Exception {
    this.defaultExtraInfoDescriptorBuilder.replaceLineStartingWith(
        "router-signature", Arrays.asList("router-signature "));
    this.runTest();
    assertTrue("Sanitized extra-info descriptor with invalid "
        + "router-signature line.",
        this.parsedExtraInfoDescriptors.isEmpty());
  }

  @Test
  public void testNetworkStatusDefault() throws Exception {
    this.runTest();
    List<String> expectedLines = Arrays.asList(
        "@type bridge-network-status 1.1",
        "published 2016-06-30 23:40:28",
        "flag-thresholds stable-uptime=807660 stable-mtbf=1425164 "
            + "fast-speed=47000 guard-wfu=98.000% guard-tk=691200 "
            + "guard-bw-inc-exits=400000 guard-bw-exc-exits=402000 "
            + "enough-mtbf=1 ignoring-advertised-bws=0",
        "r MeekGoogle iPdFhA9HzgxqT+YdgnlQsG+eRTQ "
            + "tpIv9cBFgU30vLcqDWyUF8/72Ao 2016-06-30 21:43:52 127.0.0.1 "
            + "1 0",
        "s Fast Running Stable Valid",
        "w Bandwidth=56",
        "p reject 1-65535");
    assertEquals("Sanitized descriptor does not contain expected lines.",
        expectedLines, this.parsedNetworkStatuses.get(0));
    assertTrue("Sanitized descriptor file name differs.",
        this.parsedFiles.containsKey("2016/06/statuses/30/"
        + "20160630-234028-4A0CCD2DDC7995083D73F5D667100C8A5831F16D"));
  }

  @Test
  public void testNetworkStatusPublishedLineMissing() throws Exception {
    this.defaultNetworkStatusBuilder.removeLine(
        "published 2016-06-30 23:40:28");
    this.runTest();
    String sanitizedNetworkStatusFileName = "2016/07/statuses/01/"
        + "20160701-000702-4A0CCD2DDC7995083D73F5D667100C8A5831F16D";
    assertTrue("Sanitized descriptor file does contain published line.",
        this.parsedFiles.get(sanitizedNetworkStatusFileName)
        .contains("published 2016-07-01 00:07:02"));
  }

  @Test
  public void testNetworkStatusPublishedLineMissingTarballFileNameChange()
      throws Exception {
    this.defaultNetworkStatusBuilder.removeLine(
        "published 2016-06-30 23:40:28");
    this.defaultTarballBuilder.setTarballFileName(
        "from-tonga-with-love-2016-07-01T000702Z.tar.gz");
    this.runTest();
    assertTrue("Sanitized network status without published line and with "
        + "changed tarball file name.", this.parsedNetworkStatuses.isEmpty());
  }

  @Test
  public void testNetworkStatusRlineTruncated() throws Exception {
    this.defaultNetworkStatusBuilder.replaceLineStartingWith("r ",
        Arrays.asList("r MeekGoogle"));
    this.runTest();
  }

  @Test
  public void testNetworkStatusRlineInvalidBase64() throws Exception {
    this.defaultNetworkStatusBuilder.replaceLineStartingWith("r ",
        Arrays.asList("r MeekGoogle R#SnE*e4+lFag:xr_XxSL+J;ZVs "
        + "g+M7'w+lG$mv6NW9&RmvzLO(R0Y 2016-06-30 21:43:52 "
        + "198.50.200.131 8008 0"));
    this.runTest();
    assertTrue("Should not have accepted invalid base64.",
        this.parsedNetworkStatuses.isEmpty());
  }

  @Test
  public void testNetworkStatusAlinePortMissing() throws Exception {
    this.configuration.setProperty(Key.ReplaceIpAddressesWithHashes.name(),
        "true");
    this.defaultNetworkStatusBuilder.insertBeforeLineStartingWith("s ",
        Arrays.asList("a 198.50.200.132"));
    this.runTest();
    for (String line : this.parsedNetworkStatuses.get(0)) {
      if (line.startsWith("a ")) {
        fail("Sanitized a line without port: " + line);
      }
    }
  }

  @Test
  public void testNetworkStatusVLineUnknown() throws Exception {
    this.defaultNetworkStatusBuilder.insertBeforeLineStartingWith("w ",
        Arrays.asList("v Tor 0.2.7.6"));
    this.runTest();
    assertTrue("Should not have sanitized status with v line which is unknown "
        + "in this descriptor type.", this.parsedNetworkStatuses.isEmpty());
  }

  @Test
  public void testNetworkStatusFromBifroest() throws Exception {
    this.defaultTarballBuilder.setTarballFileName(
        this.defaultTarballBuilder.getTarballFileName()
        .replaceAll("tonga", "bifroest"));
    this.runTest();
    assertTrue("Sanitized status should contain Bifroest's fingerprint.",
        this.parsedFiles.containsKey("2016/06/statuses/30/"
        + "20160630-234028-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1"));
  }

  @Test
  public void testNetworkStatusFromTrifroest() throws Exception {
    this.defaultTarballBuilder.setTarballFileName(
        this.defaultTarballBuilder.getTarballFileName()
        .replaceAll("tonga", "trifroest"));
    this.runTest();
    assertTrue("Should not have recognized unknown bridge authority Trifroest.",
        this.parsedNetworkStatuses.isEmpty());
  }

  @Test
  public void testTarballContainsSameFileTwice() throws Exception {
    this.defaultTarballBuilder.add("cached-extrainfo.new", 1467331623000L,
        Arrays.asList(new DescriptorBuilder[] {
            this.defaultExtraInfoDescriptorBuilder }));
    this.runTest();
    assertEquals("There should only be one.",
        1, this.parsedExtraInfoDescriptors.size());
  }

  @Test
  public void testTarballCorrupt() throws Exception {
    this.tarballBuilders.clear();
    Path tarballPath = Paths.get(bridgeDirectoriesDir,
        "from-tonga-2016-07-01T000702Z.tar.gz");
    Files.write(tarballPath, new byte[] { 0x00 });
    tarballPath.toFile().setLastModified(1467331624000L);
    this.runTest();
    assertTrue("Sanitized descriptors from corrupt tarball.",
        this.parsedFiles.isEmpty());
  }

  @Test
  public void testTarballUncompressed() throws Exception {
    String tarballFileName = this.tarballBuilders.get(0).getTarballFileName();
    this.tarballBuilders.get(0).setTarballFileName(
        tarballFileName.substring(0, tarballFileName.length() - 3));
    this.runTest();
    assertEquals("Expected 3 sanitized descriptors from uncompressed "
        + "tarball.", 3, this.parsedFiles.size());
  }

  @Test
  public void testTarballBzip2Compressed() throws Exception {
    String tarballFileName = this.tarballBuilders.get(0).getTarballFileName();
    this.tarballBuilders.get(0).setTarballFileName(
        tarballFileName.substring(0, tarballFileName.length() - 3) + ".bz2");
    this.runTest();
    assertTrue("Didn't expect sanitized descriptors from unsupported "
        + "bz2-compressed tarball.", this.parsedFiles.isEmpty());
  }

  @Test
  public void testParsedBridgeDirectoriesSkipTarball() throws Exception {
    Path parsedBridgeDirectoriesFile = Paths.get(statsDirectory,
        "parsed-bridge-directories");
    BufferedWriter writer = Files.newBufferedWriter(parsedBridgeDirectoriesFile,
        StandardCharsets.UTF_8);
    writer.write(this.tarballBuilders.get(0).getTarballFileName() + "\n");
    writer.close();
    this.runTest();
    assertTrue("Didn't expect sanitized descriptors after skipping "
        + "tarball.", this.parsedFiles.isEmpty());
  }

  @Test
  public void testParsedBridgeDirectoriesIsDirectory() throws Exception {
    File parsedBridgeDirectoriesFile = new File(statsDirectory,
        "parsed-bridge-directories");
    parsedBridgeDirectoriesFile.mkdirs();
    this.runTest();
    assertTrue("Continued despite not being able to read "
        + "parsed-bridge-directories.", this.parsedFiles.isEmpty());
  }

  @Test
  public void testBridgeIpSecretsWritten() throws Exception {
    this.configuration.setProperty(Key.ReplaceIpAddressesWithHashes.name(),
        "true");
    this.configuration.setProperty(Key.BridgeDescriptorMappingsLimit.name(),
        "30000");
    this.runTest();
    Path bridgeIpSecretsFile = Paths.get(statsDirectory,
        "bridge-ip-secrets");
    BufferedReader reader = Files.newBufferedReader(bridgeIpSecretsFile,
        StandardCharsets.UTF_8);
    String line;
    while ((line = reader.readLine()) != null) {
      assertTrue("Secrets line should start with month 2016-06.",
          line.startsWith("2016-06,"));
      assertEquals("Secrets line should have 7 + 1 + 166 = 174 chars.",
          174, line.length());
    }
    reader.close();
  }

  @Test
  public void testBridgeIpSecretsRead() throws Exception {
    Path bridgeIpSecretsFile = Paths.get(statsDirectory, "bridge-ip-secrets");
    BufferedWriter writer = Files.newBufferedWriter(bridgeIpSecretsFile,
        StandardCharsets.UTF_8);
    String secretLine = "2016-06,8ad0d1410d64256bdaa3977427f6db012c5809082a464c"
        + "658d651304e25654902ed0df551c8eed19913ab7aaf6243cb3adc0f4a4b93ee77991"
        + "b8c572ea25ca2ea5cd311dabe2f8b72243837ec88bcb0c758657";
    writer.write(secretLine + "\n");
    writer.close();
    this.configuration.setProperty(Key.ReplaceIpAddressesWithHashes.name(),
        "true");
    this.configuration.setProperty(Key.BridgeDescriptorMappingsLimit.name(),
        "30000");
    this.runTest();
    assertEquals("Didn't sanitize descriptors.", 3,
        this.parsedFiles.size());
    BufferedReader reader = Files.newBufferedReader(bridgeIpSecretsFile,
        StandardCharsets.UTF_8);
    String line;
    while ((line = reader.readLine()) != null) {
      assertEquals("Secrets line was changed.", secretLine, line);
    }
    reader.close();
  }

  @Test
  public void testBridgeIpSecretsIsDirectory() throws Exception {
    Files.createDirectory(Paths.get(statsDirectory, "bridge-ip-secrets"));
    this.runTest();
    assertTrue("Sanitized server descriptors without secrets.",
        this.parsedServerDescriptors.isEmpty());
    assertFalse("Didn't sanitize extra-info descriptors.",
        this.parsedExtraInfoDescriptors.isEmpty());
    assertTrue("Sanitized network statuses without secrets.",
        this.parsedNetworkStatuses.isEmpty());
  }

  @Test
  public void testBridgeIpSecretsTruncatedLine() throws Exception {
    this.configuration.setProperty(Key.ReplaceIpAddressesWithHashes.name(),
        "true");
    this.configuration.setProperty(Key.BridgeDescriptorMappingsLimit.name(),
        "30000");
    Path bridgeIpSecretsFile = Paths.get(statsDirectory,
        "bridge-ip-secrets");
    BufferedWriter writer = Files.newBufferedWriter(bridgeIpSecretsFile,
        StandardCharsets.UTF_8);
    writer.write("2016-06,x");
    writer.close();
    this.runTest();
    assertTrue("Sanitized server descriptors without secrets.",
        this.parsedServerDescriptors.isEmpty());
    assertFalse("Didn't sanitize extra-info descriptors.",
        this.parsedExtraInfoDescriptors.isEmpty());
    assertTrue("Sanitized network statuses without secrets.",
        this.parsedNetworkStatuses.isEmpty());
  }
}

