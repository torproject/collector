/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.relaydescs;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.impl.DescriptorParseException;
import org.torproject.ernie.db.main.Configuration;
import org.torproject.ernie.db.main.LockFile;
import org.torproject.ernie.db.main.LoggingConfiguration;

public class ArchiveWriter extends Thread {

  public static void main(String[] args) {

    /* Initialize logging configuration. */
    new LoggingConfiguration("relay-descriptors");
    Logger logger = Logger.getLogger(ArchiveWriter.class.getName());
    logger.info("Starting relay-descriptors module of ERNIE.");

    // Initialize configuration
    Configuration config = new Configuration();

    // Use lock file to avoid overlapping runs
    LockFile lf = new LockFile("relay-descriptors");
    if (!lf.acquireLock()) {
      logger.severe("Warning: ERNIE is already running or has not exited "
          + "cleanly! Exiting!");
      System.exit(1);
    }

    // Import/download relay descriptors from the various sources
    new ArchiveWriter(config).run();

    // Remove lock file
    lf.releaseLock();

    logger.info("Terminating relay-descriptors module of ERNIE.");
  }

  private Configuration config;

  public ArchiveWriter(Configuration config) {
    this.config = config;
  }

  private long now = System.currentTimeMillis();
  private Logger logger;
  private File outputDirectory;
  private DescriptorParser descriptorParser;
  private int storedConsensusesCounter = 0, storedVotesCounter = 0,
      storedCertsCounter = 0, storedServerDescriptorsCounter = 0,
      storedExtraInfoDescriptorsCounter = 0;

  private SortedMap<Long, SortedSet<String>> storedConsensuses =
      new TreeMap<Long, SortedSet<String>>();
  private SortedMap<Long, Integer> expectedVotes =
      new TreeMap<Long, Integer>();
  private SortedMap<Long, SortedMap<String, SortedSet<String>>>
      storedVotes =
      new TreeMap<Long, SortedMap<String, SortedSet<String>>>();
  private SortedMap<Long, Map<String, String>> storedServerDescriptors =
      new TreeMap<Long, Map<String, String>>();
  private SortedMap<Long, Set<String>> storedExtraInfoDescriptors =
      new TreeMap<Long, Set<String>>();

  private File storedServerDescriptorsFile = new File(
      "stats/stored-server-descriptors");
  private File storedExtraInfoDescriptorsFile = new File(
      "stats/stored-extra-info-descriptors");

  private void loadDescriptorDigests() {
    SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    try {
      if (this.storedServerDescriptorsFile.exists()) {
        BufferedReader br = new BufferedReader(new FileReader(
            this.storedServerDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          String[] parts = line.split(",");
          if (parts.length != 3) {
            this.logger.warning("Could not load server descriptor "
                + "digests because of illegal line '" + line + "'.  We "
                + "might not be able to correctly check descriptors for "
                + "completeness.");
            break;
          }
          long published = dateTimeFormat.parse(parts[0]).getTime();
          if (published < this.now - 48L * 60L * 60L * 1000L) {
            continue;
          }
          if (!this.storedServerDescriptors.containsKey(published)) {
            this.storedServerDescriptors.put(published,
                new HashMap<String, String>());
          }
          String serverDescriptorDigest = parts[1];
          String extraInfoDescriptorDigest = parts[2].equals("NA") ? null
              : parts[2];
          this.storedServerDescriptors.get(published).put(
              serverDescriptorDigest, extraInfoDescriptorDigest);
        }
        br.close();
      }
      if (this.storedExtraInfoDescriptorsFile.exists()) {
        BufferedReader br = new BufferedReader(new FileReader(
            this.storedExtraInfoDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          String[] parts = line.split(",");
          if (parts.length != 2) {
            this.logger.warning("Could not load extra-info descriptor "
                + "digests because of illegal line '" + line + "'.  We "
                + "might not be able to correctly check descriptors for "
                + "completeness.");
            break;
          }
          long published = dateTimeFormat.parse(parts[0]).getTime();
          if (published < this.now - 48L * 60L * 60L * 1000L) {
            continue;
          }
          if (!this.storedExtraInfoDescriptors.containsKey(published)) {
            this.storedExtraInfoDescriptors.put(published,
                new HashSet<String>());
          }
          String extraInfoDescriptorDigest = parts[1];
          this.storedExtraInfoDescriptors.get(published).add(
              extraInfoDescriptorDigest);
        }
        br.close();
      }
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not load descriptor "
          + "digests.  We might not be able to correctly check "
          + "descriptors for completeness.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not load descriptor "
          + "digests.  We might not be able to correctly check "
          + "descriptors for completeness.", e);
    }
  }

  private void saveDescriptorDigests() {
    SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    try {
      this.storedServerDescriptorsFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.storedServerDescriptorsFile));
      for (Map.Entry<Long, Map<String, String>> e :
          this.storedServerDescriptors.entrySet()) {
        String published = dateTimeFormat.format(e.getKey());
        for (Map.Entry<String, String> f : e.getValue().entrySet()) {
          String serverDescriptorDigest = f.getKey();
          String extraInfoDescriptorDigest = f.getValue() == null ? "NA"
              : f.getValue();
          bw.write(String.format("%s,%s,%s%n", published,
              serverDescriptorDigest, extraInfoDescriptorDigest));
        }
      }
      bw.close();
      this.storedExtraInfoDescriptorsFile.getParentFile().mkdirs();
      bw = new BufferedWriter(new FileWriter(
          this.storedExtraInfoDescriptorsFile));
      for (Map.Entry<Long, Set<String>> e :
          this.storedExtraInfoDescriptors.entrySet()) {
        String published = dateTimeFormat.format(e.getKey());
        for (String extraInfoDescriptorDigest : e.getValue()) {
          bw.write(String.format("%s,%s%n", published,
              extraInfoDescriptorDigest));
        }
      }
      bw.close();
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not save descriptor "
          + "digests.  We might not be able to correctly check "
          + "descriptors for completeness in the next run.", e);
    }
  }

  public void run() {

    File outputDirectory =
        new File(config.getDirectoryArchivesOutputDirectory());
    File statsDirectory = new File("stats");

    this.logger = Logger.getLogger(ArchiveWriter.class.getName());
    this.outputDirectory = outputDirectory;
    this.descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();

    this.loadDescriptorDigests();

    // Prepare relay descriptor parser
    RelayDescriptorParser rdp = new RelayDescriptorParser(this);

    RelayDescriptorDownloader rdd = null;
    if (config.getDownloadRelayDescriptors()) {
      List<String> dirSources =
          config.getDownloadFromDirectoryAuthorities();
      rdd = new RelayDescriptorDownloader(rdp, dirSources,
          config.getDownloadVotesByFingerprint(),
          config.getDownloadCurrentConsensus(),
          config.getDownloadCurrentVotes(),
          config.getDownloadMissingServerDescriptors(),
          config.getDownloadMissingExtraInfoDescriptors(),
          config.getDownloadAllServerDescriptors(),
          config.getDownloadAllExtraInfoDescriptors(),
          config.getCompressRelayDescriptorDownloads());
      rdp.setRelayDescriptorDownloader(rdd);
    }
    if (config.getImportCachedRelayDescriptors()) {
      new CachedRelayDescriptorReader(rdp,
          config.getCachedRelayDescriptorDirectory(), statsDirectory);
      this.intermediateStats("importing relay descriptors from local "
          + "Tor data directories");
    }
    if (config.getImportDirectoryArchives()) {
      new ArchiveReader(rdp,
          new File(config.getDirectoryArchivesDirectory()),
          statsDirectory,
          config.getKeepDirectoryArchiveImportHistory());
      this.intermediateStats("importing relay descriptors from local "
          + "directory");
    }
    if (rdd != null) {
      rdd.downloadDescriptors();
      rdd.writeFile();
      rdd = null;
      this.intermediateStats("downloading relay descriptors from the "
          + "directory authorities");
    }

    this.checkMissingDescriptors();

    this.checkStaledescriptors();

    this.cleanUpRsyncDirectory();

    this.saveDescriptorDigests();
  }

  private boolean store(byte[] typeAnnotation, byte[] data,
      File[] outputFiles) {
    try {
      this.logger.finer("Storing " + outputFiles[0]);
      if (this.descriptorParser.parseDescriptors(data,
          outputFiles[0].getName()).size() != 1) {
        this.logger.info("Relay descriptor file " + outputFiles[0]
            + " doesn't contain exactly one descriptor.  Not storing.");
        return false;
      }
      for (File outputFile : outputFiles) {
        outputFile.getParentFile().mkdirs();
        BufferedOutputStream bos = new BufferedOutputStream(
            new FileOutputStream(outputFile));
        if (data.length > 0 && data[0] != '@') {
          bos.write(typeAnnotation, 0, typeAnnotation.length);
        }
        bos.write(data, 0, data.length);
        bos.close();
      }
      return true;
    } catch (DescriptorParseException e) {
      this.logger.log(Level.WARNING, "Could not parse relay descriptor "
          + outputFiles[0] + " before storing it to disk.  Skipping.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not store relay descriptor "
          + outputFiles[0], e);
    }
    return false;
  }

  private static final byte[] CONSENSUS_ANNOTATION =
      "@type network-status-consensus-3 1.0\n".getBytes();
  public void storeConsensus(byte[] data, long validAfter,
      SortedSet<String> dirSources,
      SortedSet<String> serverDescriptorDigests) {
    SimpleDateFormat printFormat = new SimpleDateFormat(
        "yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory + "/consensus/"
        + printFormat.format(new Date(validAfter)) + "-consensus");
    File rsyncFile = new File("rsync/relay-descriptors/consensuses/"
        + tarballFile.getName());
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    if (this.store(CONSENSUS_ANNOTATION, data, outputFiles)) {
      this.storedConsensusesCounter++;
    }
    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    if (this.now - validAfter < 3L * 60L * 60L * 1000L) {
      this.storedConsensuses.put(validAfter, serverDescriptorDigests);
      this.expectedVotes.put(validAfter, dirSources.size());
    }
  }

  private static final byte[] VOTE_ANNOTATION =
      "@type network-status-vote-3 1.0\n".getBytes();
  public void storeVote(byte[] data, long validAfter,
      String fingerprint, String digest,
      SortedSet<String> serverDescriptorDigests) {
    SimpleDateFormat printFormat = new SimpleDateFormat(
        "yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory + "/vote/"
        + printFormat.format(new Date(validAfter)) + "-vote-"
        + fingerprint + "-" + digest);
    File rsyncFile = new File("rsync/relay-descriptors/votes/"
        + tarballFile.getName());
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    if (this.store(VOTE_ANNOTATION, data, outputFiles)) {
      this.storedVotesCounter++;
    }
    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    if (this.now - validAfter < 3L * 60L * 60L * 1000L) {
      if (!this.storedVotes.containsKey(validAfter)) {
        this.storedVotes.put(validAfter,
            new TreeMap<String, SortedSet<String>>());
      }
      this.storedVotes.get(validAfter).put(fingerprint,
          serverDescriptorDigests);
    }
  }

  private static final byte[] CERTIFICATE_ANNOTATION =
      "@type dir-key-certificate-3 1.0\n".getBytes();
  public void storeCertificate(byte[] data, String fingerprint,
      long published) {
    SimpleDateFormat printFormat = new SimpleDateFormat(
        "yyyy-MM-dd-HH-mm-ss");
    printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory + "/certs/"
        + fingerprint + "-" + printFormat.format(new Date(published)));
    File[] outputFiles = new File[] { tarballFile };
    if (this.store(CERTIFICATE_ANNOTATION, data, outputFiles)) {
      this.storedCertsCounter++;
    }
  }

  private static final byte[] SERVER_DESCRIPTOR_ANNOTATION =
      "@type server-descriptor 1.0\n".getBytes();
  public void storeServerDescriptor(byte[] data, String digest,
      long published, String extraInfoDigest) {
    SimpleDateFormat printFormat = new SimpleDateFormat("yyyy/MM/");
    printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory
        + "/server-descriptor/" + printFormat.format(new Date(published))
        + digest.substring(0, 1) + "/" + digest.substring(1, 2) + "/"
        + digest);
    File rsyncFile = new File(
        "rsync/relay-descriptors/server-descriptors/" + digest);
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    if (this.store(SERVER_DESCRIPTOR_ANNOTATION, data, outputFiles)) {
      this.storedServerDescriptorsCounter++;
    }
    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    if (this.now - published < 48L * 60L * 60L * 1000L) {
      if (!this.storedServerDescriptors.containsKey(published)) {
        this.storedServerDescriptors.put(published,
            new HashMap<String, String>());
      }
      this.storedServerDescriptors.get(published).put(digest,
          extraInfoDigest);
    }
  }

  private static final byte[] EXTRA_INFO_ANNOTATION =
      "@type extra-info 1.0\n".getBytes();
  public void storeExtraInfoDescriptor(byte[] data,
      String extraInfoDigest, long published) {
    SimpleDateFormat descriptorFormat = new SimpleDateFormat("yyyy/MM/");
    descriptorFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory + "/extra-info/"
        + descriptorFormat.format(new Date(published))
        + extraInfoDigest.substring(0, 1) + "/"
        + extraInfoDigest.substring(1, 2) + "/"
        + extraInfoDigest);
    File rsyncFile = new File("rsync/relay-descriptors/extra-infos/"
        + extraInfoDigest);
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    if (this.store(EXTRA_INFO_ANNOTATION, data, outputFiles)) {
      this.storedExtraInfoDescriptorsCounter++;
    }
    if (this.now - published < 48L * 60L * 60L * 1000L) {
      if (!this.storedExtraInfoDescriptors.containsKey(published)) {
        this.storedExtraInfoDescriptors.put(published,
            new HashSet<String>());
      }
      this.storedExtraInfoDescriptors.get(published).add(extraInfoDigest);
    }
  }

  private StringBuilder intermediateStats = new StringBuilder();
  public void intermediateStats(String event) {
    intermediateStats.append("While " + event + ", we stored "
        + this.storedConsensusesCounter + " consensus(es), "
        + this.storedVotesCounter + " vote(s), " + this.storedCertsCounter
        + " certificate(s), " + this.storedServerDescriptorsCounter
        + " server descriptor(s), and "
        + this.storedExtraInfoDescriptorsCounter
        + " extra-info descriptor(s) to disk.\n");
    this.storedConsensusesCounter = 0;
    this.storedVotesCounter = 0;
    this.storedCertsCounter = 0;
    this.storedServerDescriptorsCounter = 0;
    this.storedExtraInfoDescriptorsCounter = 0;
  }

  private void checkMissingDescriptors() {
    StringBuilder sb = new StringBuilder("Finished writing relay "
        + "descriptors to disk.\n");
    sb.append(intermediateStats.toString());
    sb.append("Statistics on the completeness of written relay "
        + "descriptors of the last 3 consensuses (Consensus/Vote, "
        + "valid-after, votes, server descriptors, extra-infos):");
    SimpleDateFormat dateTimeFormat =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    Map<String, String> knownServerDescriptors =
        new HashMap<String, String>();
    for (Map<String, String> descriptors :
        this.storedServerDescriptors.values()) {
      knownServerDescriptors.putAll(descriptors);
    }
    Set<String> knownExtraInfoDescriptors = new HashSet<String>();
    for (Set<String> descriptors :
        this.storedExtraInfoDescriptors.values()) {
      knownExtraInfoDescriptors.addAll(descriptors);
    }
    boolean missingDescriptors = false, missingVotes = false;
    for (Map.Entry<Long, SortedSet<String>> c :
        this.storedConsensuses.entrySet()) {
      long validAfterMillis = c.getKey();
      String validAfterTime = dateTimeFormat.format(validAfterMillis);
      int allVotes = this.expectedVotes.containsKey(validAfterMillis)
          ? this.expectedVotes.get(validAfterMillis) : 0;
      int foundVotes = 0;
      if (this.storedVotes.containsKey(validAfterMillis)) {
        foundVotes = this.storedVotes.get(validAfterMillis).size();
        for (Map.Entry<String, SortedSet<String>> v :
            this.storedVotes.get(validAfterMillis).entrySet()) {
          int voteFoundServerDescs = 0, voteAllServerDescs = 0,
              voteFoundExtraInfos = 0, voteAllExtraInfos = 0;
          for (String serverDescriptorDigest : v.getValue()) {
            voteAllServerDescs++;
            if (knownServerDescriptors.containsKey(
                serverDescriptorDigest)) {
              voteFoundServerDescs++;
              if (knownServerDescriptors.get(serverDescriptorDigest)
                  != null) {
                String extraInfoDescriptorDigest =
                    knownServerDescriptors.get(serverDescriptorDigest);
                voteAllExtraInfos++;
                if (knownExtraInfoDescriptors.contains(
                    extraInfoDescriptorDigest)) {
                  voteFoundExtraInfos++;
                }
              }
            }
          }
          sb.append(String.format("%nV, %s, NA, %d/%d (%.1f%%), "
              + "%d/%d (%.1f%%)", validAfterTime,
              voteFoundServerDescs, voteAllServerDescs,
              100.0D * (double) voteFoundServerDescs /
                (double) voteAllServerDescs,
              voteFoundExtraInfos, voteAllExtraInfos,
              100.0D * (double) voteFoundExtraInfos /
                (double) voteAllExtraInfos));
          if (voteFoundServerDescs * 1000 < voteAllServerDescs * 995 ||
              voteFoundExtraInfos * 1000 < voteAllExtraInfos * 995) {
            missingDescriptors = true;
          }
        }
      }
      int foundServerDescs = 0, allServerDescs = 0, foundExtraInfos = 0,
          allExtraInfos = 0;
      for (String serverDescriptorDigest : c.getValue()) {
        allServerDescs++;
        if (knownServerDescriptors.containsKey(
            serverDescriptorDigest)) {
          foundServerDescs++;
          if (knownServerDescriptors.get(
              serverDescriptorDigest) != null) {
            allExtraInfos++;
            String extraInfoDescriptorDigest =
                knownServerDescriptors.get(serverDescriptorDigest);
            if (knownExtraInfoDescriptors.contains(
                extraInfoDescriptorDigest)) {
              foundExtraInfos++;
            }
          }
        }
      }
      sb.append(String.format("%nC, %s, %d/%d (%.1f%%), "
          + "%d/%d (%.1f%%), %d/%d (%.1f%%)",
          validAfterTime, foundVotes, allVotes,
          100.0D * (double) foundVotes / (double) allVotes,
          foundServerDescs, allServerDescs,
          100.0D * (double) foundServerDescs / (double) allServerDescs,
          foundExtraInfos, allExtraInfos,
          100.0D * (double) foundExtraInfos / (double) allExtraInfos));
      if (foundServerDescs * 1000 < allServerDescs * 995 ||
          foundExtraInfos * 1000 < allExtraInfos * 995) {
        missingDescriptors = true;
      }
      if (foundVotes < allVotes) {
        missingVotes = true;
      }
    }
    this.logger.info(sb.toString());
    if (missingDescriptors) {
      this.logger.warning("We are missing at least 0.5% of server or "
          + "extra-info descriptors referenced from a consensus or "
          + "vote.");
    }
    if (missingVotes) {
      this.logger.warning("We are missing at least one vote that was "
          + "referenced from a consensus.");
    }
  }

  private void checkStaledescriptors() {
    SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    long tooOldMillis = this.now - 330L * 60L * 1000L;
    if (!this.storedConsensuses.isEmpty() &&
        this.storedConsensuses.lastKey() < tooOldMillis) {
      this.logger.warning("The last known relay network status "
          + "consensus was valid after "
          + dateTimeFormat.format(this.storedConsensuses.lastKey())
          + ", which is more than 5:30 hours in the past.");
    }
    if (!this.storedVotes.isEmpty() &&
        this.storedVotes.lastKey() < tooOldMillis) {
      this.logger.warning("The last known relay network status vote "
          + "was valid after " + dateTimeFormat.format(
          this.storedVotes.lastKey()) + ", which is more than 5:30 hours "
          + "in the past.");
    }
    if (!this.storedServerDescriptors.isEmpty() &&
        this.storedServerDescriptors.lastKey() < tooOldMillis) {
      this.logger.warning("The last known relay server descriptor was "
          + "published at "
          + dateTimeFormat.format(this.storedServerDescriptors.lastKey())
          + ", which is more than 5:30 hours in the past.");
    }
    if (!this.storedExtraInfoDescriptors.isEmpty() &&
        this.storedExtraInfoDescriptors.lastKey() < tooOldMillis) {
      this.logger.warning("The last known relay extra-info descriptor "
          + "was published at " + dateTimeFormat.format(
          this.storedExtraInfoDescriptors.lastKey())
          + ", which is more than 5:30 hours in the past.");
    }
  }

  /* Delete all files from the rsync directory that have not been modified
   * in the last three days. */
  public void cleanUpRsyncDirectory() {
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;
    Stack<File> allFiles = new Stack<File>();
    allFiles.add(new File("rsync/relay-descriptors"));
    while (!allFiles.isEmpty()) {
      File file = allFiles.pop();
      if (file.isDirectory()) {
        allFiles.addAll(Arrays.asList(file.listFiles()));
      } else if (file.lastModified() < cutOffMillis) {
        file.delete();
      }
    }
  }
}
