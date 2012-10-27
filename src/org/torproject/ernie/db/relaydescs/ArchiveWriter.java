/* Copyright 2010--2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.relaydescs;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TimeZone;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.impl.DescriptorParseException;
import org.torproject.ernie.db.main.Configuration;

public class ArchiveWriter extends Thread {

  private Configuration config;

  public ArchiveWriter(Configuration config) {
    this.config = config;
  }

  private Logger logger;
  private File outputDirectory;
  private DescriptorParser descriptorParser;
  private int storedConsensuses = 0, storedVotes = 0, storedCerts = 0,
      storedServerDescriptors = 0, storedExtraInfoDescriptors = 0;

  public void run() {

    File outputDirectory =
        new File(config.getDirectoryArchivesOutputDirectory());
    File statsDirectory = new File("stats");

    this.logger = Logger.getLogger(ArchiveWriter.class.getName());
    this.outputDirectory = outputDirectory;
    this.descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();

    // Prepare relay descriptor parser
    RelayDescriptorParser rdp = new RelayDescriptorParser(this);

    RelayDescriptorDownloader rdd = null;
    if (config.getDownloadRelayDescriptors()) {
      List<String> dirSources =
          config.getDownloadFromDirectoryAuthorities();
      rdd = new RelayDescriptorDownloader(rdp, dirSources,
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

    // Write output to disk that only depends on relay descriptors
    this.dumpStats();

    this.checkStaledescriptors();

    this.cleanUpRsyncDirectory();
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

  private long maxConsensusValidAfter = 0L;
  private static final byte[] CONSENSUS_ANNOTATION =
      "@type network-status-consensus-3 1.0\n".getBytes();
  public void storeConsensus(byte[] data, long validAfter) {
    this.maxConsensusValidAfter = Math.max(this.maxConsensusValidAfter,
        validAfter);
    SimpleDateFormat printFormat = new SimpleDateFormat(
        "yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
    printFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    File tarballFile = new File(this.outputDirectory + "/consensus/"
        + printFormat.format(new Date(validAfter)) + "-consensus");
    File rsyncFile = new File("rsync/relay-descriptors/consensuses/"
        + tarballFile.getName());
    File[] outputFiles = new File[] { tarballFile, rsyncFile };
    if (this.store(CONSENSUS_ANNOTATION, data, outputFiles)) {
      this.storedConsensuses++;
    }
  }

  private long maxVoteValidAfter = 0L;
  private static final byte[] VOTE_ANNOTATION =
      "@type network-status-vote-3 1.0\n".getBytes();
  public void storeVote(byte[] data, long validAfter,
      String fingerprint, String digest) {
    this.maxVoteValidAfter = Math.max(this.maxVoteValidAfter, validAfter);
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
      this.storedVotes++;
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
      this.storedCerts++;
    }
  }

  private long maxServerDescriptorPublished = 0L;
  private static final byte[] SERVER_DESCRIPTOR_ANNOTATION =
      "@type server-descriptor 1.0\n".getBytes();
  public void storeServerDescriptor(byte[] data, String digest,
      long published) {
    this.maxServerDescriptorPublished = Math.max(
        this.maxServerDescriptorPublished, published);
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
      this.storedServerDescriptors++;
    }
  }

  private long maxExtraInfoDescriptorPublished = 0L;
  private static final byte[] EXTRA_INFO_ANNOTATION =
      "@type extra-info 1.0\n".getBytes();
  public void storeExtraInfoDescriptor(byte[] data,
      String extraInfoDigest, long published) {
    this.maxExtraInfoDescriptorPublished = Math.max(
        this.maxExtraInfoDescriptorPublished, published);
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
      this.storedExtraInfoDescriptors++;
    }
  }

  private StringBuilder intermediateStats = new StringBuilder();
  public void intermediateStats(String event) {
    intermediateStats.append("While " + event + ", we stored "
        + this.storedConsensuses + " consensus(es), " + this.storedVotes
        + " vote(s), " + this.storedCerts + " certificate(s), "
        + this.storedServerDescriptors + " server descriptor(s), and "
        + this.storedExtraInfoDescriptors
        + " extra-info descriptor(s) to disk.\n");
    this.storedConsensuses = 0;
    this.storedVotes = 0;
    this.storedCerts = 0;
    this.storedServerDescriptors = 0;
    this.storedExtraInfoDescriptors = 0;
  }
  /**
   * Dump some statistics on the completeness of descriptors to the logs
   * on level INFO.
   */
  public void dumpStats() {
    StringBuilder sb = new StringBuilder("Finished writing relay "
        + "descriptors to disk.\n");
    sb.append(intermediateStats.toString());
    sb.append("Statistics on the completeness of written relay "
        + "descriptors of the last 3 consensuses (Consensus/Vote, "
        + "valid-after, votes, server descriptors, extra-infos):");
    try {
      SimpleDateFormat validAfterFormat =
          new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
      validAfterFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      SimpleDateFormat consensusVoteFormat =
          new SimpleDateFormat("yyyy/MM/dd/yyyy-MM-dd-HH-mm-ss");
      consensusVoteFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      SimpleDateFormat descriptorFormat =
          new SimpleDateFormat("yyyy/MM/");
      descriptorFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

      SortedSet<File> consensuses = new TreeSet<File>();
      Stack<File> leftToParse = new Stack<File>();
      leftToParse.add(new File(outputDirectory + "/consensus"));
      while (!leftToParse.isEmpty()) {
        File pop = leftToParse.pop();
        if (pop.isDirectory()) {
          for (File f : pop.listFiles()) {
            leftToParse.add(f);
          }
        } else if (pop.length() > 0) {
          consensuses.add(pop);
        }
        while (consensuses.size() > 3) {
          consensuses.remove(consensuses.first());
        }
      }
      for (File f : consensuses) {
        BufferedReader br = new BufferedReader(new FileReader(f));
        String line = null, validAfterTime = null,
            voteFilenamePrefix = null, dirSource = null;
        int allVotes = 0, foundVotes = 0,
            allServerDescs = 0, foundServerDescs = 0,
            allExtraInfos = 0, foundExtraInfos = 0;
        while ((line = br.readLine()) != null) {
          if (line.startsWith("valid-after ")) {
            validAfterTime = line.substring("valid-after ".length());
            long validAfter = validAfterFormat.parse(
                validAfterTime).getTime();
            voteFilenamePrefix = outputDirectory + "/vote/"
                + consensusVoteFormat.format(new Date(validAfter))
                + "-vote-";
          } else if (line.startsWith("dir-source ")) {
            dirSource = line.split(" ")[2];
          } else if (line.startsWith("vote-digest ")) {
            allVotes++;
            File voteFile = new File(voteFilenamePrefix + dirSource + "-"
                + line.split(" ")[1]);
            if (voteFile.exists()) {
              foundVotes++;
              BufferedReader vbr = new BufferedReader(new FileReader(
                  voteFile));
              String line3 = null;
              int voteAllServerDescs = 0, voteFoundServerDescs = 0,
                  voteAllExtraInfos = 0, voteFoundExtraInfos = 0;
              while ((line3 = vbr.readLine()) != null) {
                if (line3.startsWith("r ")) {
                  voteAllServerDescs++;
                  String digest = Hex.encodeHexString(Base64.decodeBase64(
                      line3.split(" ")[3] + "=")).toLowerCase();
                  long published = validAfterFormat.parse(
                      line3.split(" ")[4] + " "
                      + line3.split(" ")[5]).getTime();
                  String filename = outputDirectory
                      + "/server-descriptor/"
                      + descriptorFormat.format(new Date(published))
                      + digest.substring(0, 1) + "/"
                      + digest.substring(1, 2) + "/" + digest;
                  if (new File(filename).exists()) {
                    BufferedReader sbr = new BufferedReader(new FileReader(
                        new File(filename)));
                    String line2 = null;
                    while ((line2 = sbr.readLine()) != null) {
                      if (line2.startsWith("opt extra-info-digest ") ||
                          line2.startsWith("extra-info-digest ")) {
                        voteAllExtraInfos++;
                        String extraInfoDigest = line2.startsWith("opt ") ?
                            line2.split(" ")[2].toLowerCase() :
                            line2.split(" ")[1].toLowerCase();
                        String filename2 =
                            outputDirectory.getAbsolutePath()
                            + "/extra-info/"
                            + descriptorFormat.format(new Date(published))
                            + extraInfoDigest.substring(0, 1) + "/"
                            + extraInfoDigest.substring(1, 2) + "/"
                            + extraInfoDigest;
                        if (new File(filename2).exists()) {
                          voteFoundExtraInfos++;
                        }
                      }
                    }
                    sbr.close();
                    voteFoundServerDescs++;
                  }
                }
              }
              vbr.close();
              sb.append(String.format("%nV, %s, NA, %d/%d (%.1f%%), "
                  + "%d/%d (%.1f%%)", validAfterTime,
                  voteFoundServerDescs, voteAllServerDescs,
                  100.0D * (double) voteFoundServerDescs /
                    (double) voteAllServerDescs,
                  voteFoundExtraInfos, voteAllExtraInfos,
                  100.0D * (double) voteFoundExtraInfos /
                    (double) voteAllExtraInfos));
            }
          } else if (line.startsWith("r ")) {
            allServerDescs++;
            String digest = Hex.encodeHexString(Base64.decodeBase64(
                line.split(" ")[3] + "=")).toLowerCase();
            long published = validAfterFormat.parse(
                line.split(" ")[4] + " " + line.split(" ")[5]).getTime();
            String filename = outputDirectory.getAbsolutePath()
                + "/server-descriptor/"
                + descriptorFormat.format(new Date(published))
                + digest.substring(0, 1) + "/"
                + digest.substring(1, 2) + "/" + digest;
            if (new File (filename).exists()) {
              BufferedReader sbr = new BufferedReader(new FileReader(
                  new File(filename)));
              String line2 = null;
              while ((line2 = sbr.readLine()) != null) {
                if (line2.startsWith("opt extra-info-digest ") ||
                    line2.startsWith("extra-info-digest ")) {
                  allExtraInfos++;
                  String extraInfoDigest = line2.startsWith("opt ") ?
                      line2.split(" ")[2].toLowerCase() :
                      line2.split(" ")[1].toLowerCase();
                  String filename2 = outputDirectory.getAbsolutePath()
                      + "/extra-info/"
                      + descriptorFormat.format(new Date(published))
                      + extraInfoDigest.substring(0, 1) + "/"
                      + extraInfoDigest.substring(1, 2) + "/"
                      + extraInfoDigest;
                  if (new File (filename2).exists()) {
                    foundExtraInfos++;
                  }
                }
              }
              sbr.close();
              foundServerDescs++;
            }
          }
        }
        br.close();
        sb.append(String.format("%nC, %s, %d/%d (%.1f%%), "
            + "%d/%d (%.1f%%), %d/%d (%.1f%%)",
            validAfterTime, foundVotes, allVotes,
            100.0D * (double) foundVotes / (double) allVotes,
            foundServerDescs, allServerDescs,
            100.0D * (double) foundServerDescs / (double) allServerDescs,
            foundExtraInfos, allExtraInfos,
            100.0D * (double) foundExtraInfos / (double) allExtraInfos));
      }
      this.logger.info(sb.toString());
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not dump statistics to disk.",
          e);
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not dump statistics to disk.",
          e);
    }
  }

  private void checkStaledescriptors() {
    SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
        "yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    long tooOldMillis = System.currentTimeMillis() - 330L * 60L * 1000L;
    if (maxConsensusValidAfter > 0L &&
        maxConsensusValidAfter < tooOldMillis) {
      this.logger.warning("The last known relay network status "
          + "consensus was valid after "
          + dateTimeFormat.format(maxConsensusValidAfter)
          + ", which is more than 5:30 hours in the past.");
    }
    if (maxVoteValidAfter > 0L && maxVoteValidAfter < tooOldMillis) {
      this.logger.warning("The last known relay network status vote "
          + "was valid after " + dateTimeFormat.format(maxVoteValidAfter)
          + ", which is more than 5:30 hours in the past.");
    }
    if (maxServerDescriptorPublished > 0L &&
        maxServerDescriptorPublished < tooOldMillis) {
      this.logger.warning("The last known relay server descriptor was "
          + "published at "
          + dateTimeFormat.format(maxServerDescriptorPublished)
          + ", which is more than 5:30 hours in the past.");
    }
    if (maxExtraInfoDescriptorPublished > 0L &&
        maxExtraInfoDescriptorPublished < tooOldMillis) {
      this.logger.warning("The last known relay extra-info descriptor "
          + "was published at "
          + dateTimeFormat.format(maxExtraInfoDescriptorPublished)
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
