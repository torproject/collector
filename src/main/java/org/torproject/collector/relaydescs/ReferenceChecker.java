/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.relaydescs;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.ExtraInfoDescriptor;
import org.torproject.descriptor.Microdescriptor;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.ServerDescriptor;

import com.google.gson.Gson;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;

public class ReferenceChecker {

  private static final Logger logger = LoggerFactory.getLogger(
      ReferenceChecker.class);

  private File descriptorsDir;

  private File referencesFile;

  private File historyFile;

  private long currentTimeMillis;

  private SortedSet<Reference> references = new TreeSet<Reference>();

  private static DateFormat dateTimeFormat;

  static {
    dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'",
        Locale.US);
    dateTimeFormat.setLenient(false);
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  private static final long ONE_HOUR = 60L * 60L * 1000L;

  private static final long THREE_HOURS = 3L * ONE_HOUR;

  private static final long SIX_HOURS = 6L * ONE_HOUR;

  private static final long ONE_DAY = 24L * ONE_HOUR;

  private static final long THIRTY_DAYS = 30L * ONE_DAY;

  /** Initializes a reference checker using the given file paths. */
  public ReferenceChecker(File descriptorsDir, File referencesFile,
      File historyFile) {
    this.descriptorsDir = descriptorsDir;
    this.referencesFile = referencesFile;
    this.historyFile = historyFile;
  }

  /** Checks references between descriptors, and if too many referenced
   * descriptors are missing, puts out a warning to the logs. */
  public void check() {
    this.getCurrentTimeMillis();
    this.readReferencesFile();
    this.readNewDescriptors();
    this.dropStaleReferences();
    this.checkReferences();
    this.writeReferencesFile();
  }

  private void getCurrentTimeMillis() {
    this.currentTimeMillis = System.currentTimeMillis();
  }

  private static class Reference implements Comparable<Reference> {

    private String referencing;

    private String referenced;

    private double weight;

    private long expiresAfterMillis;

    public Reference() { /* empty */ }

    public Reference(String referencing, String referenced, double weight,
        long expiresAfterMillis) {
      this.referencing = referencing;
      this.referenced = referenced;
      this.weight = weight;
      this.expiresAfterMillis = expiresAfterMillis;
    }

    @Override
    public boolean equals(Object otherObject) {
      if (!(otherObject instanceof Reference)) {
        return false;
      }
      Reference other = (Reference) otherObject;
      return this.referencing.equals(other.referencing)
          && this.referenced.equals(other.referenced);
    }

    @Override
    public int hashCode() {
      return this.referencing.hashCode() + this.referenced.hashCode();
    }

    @Override
    public int compareTo(Reference other) {
      int result = this.referencing.compareTo(other.referencing);
      if (result == 0) {
        result = this.referenced.compareTo(other.referenced);
      }
      return result;
    }
  }

  private void readReferencesFile() {
    if (!this.referencesFile.exists()) {
      return;
    }
    Gson gson = new Gson();
    try (FileReader fr = new FileReader(this.referencesFile)) {
      this.references.addAll(Arrays.asList(gson.fromJson(fr,
          Reference[].class)));
    } catch (IOException e) {
      logger.warn("Cannot read existing references file "
          + "from previous run.", e);
    } catch (RuntimeException jpe) {
      logger.warn("Content of {} cannot be parsed. "
          + "File will be erased and rewritten. In general, {} "
          + "shouldn't be edited manually.  Error reason: {}",
          this.referencesFile.toString(),
          this.referencesFile.toString(), jpe.getMessage());
      try {
        Files.deleteIfExists(this.referencesFile.toPath());
      } catch (IOException ioe) {
        logger.warn("Cannot delete '{}', reason: {}",
            this.referencesFile.toString(), ioe.getMessage(), ioe);
      }
    }
  }

  private void readNewDescriptors() {
    DescriptorReader descriptorReader =
        DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addDirectory(this.descriptorsDir);
    descriptorReader.setExcludeFiles(this.historyFile);
    Iterator<DescriptorFile> descriptorFiles =
        descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (descriptor instanceof RelayNetworkStatusConsensus) {
          RelayNetworkStatusConsensus consensus =
              (RelayNetworkStatusConsensus) descriptor;
          String consensusFlavor = consensus.getConsensusFlavor();
          if (consensusFlavor == null) {
            this.readRelayNetworkStatusConsensusUnflavored(consensus);
          } else if (consensusFlavor.equals("microdesc")) {
            this.readRelayNetworkStatusConsensusMicrodesc(consensus);
          } else {
            /* Ignore unknown consensus flavors. */
          }
        } else if (descriptor instanceof RelayNetworkStatusVote) {
          this.readRelayNetworkStatusVote(
              (RelayNetworkStatusVote) descriptor);
        } else if (descriptor instanceof ServerDescriptor) {
          this.readServerDescriptor((ServerDescriptor) descriptor);
        } else if (descriptor instanceof ExtraInfoDescriptor) {
          this.readExtraInfoDescriptor((ExtraInfoDescriptor) descriptor);
        } else if (descriptor instanceof Microdescriptor) {
          readMicrodescriptor((Microdescriptor) descriptor);
        } else {
          /* Ignore unknown descriptors. */
        }
      }
    }
  }

  private void readRelayNetworkStatusConsensusUnflavored(
      RelayNetworkStatusConsensus consensus) {
    String validAfter = dateTimeFormat.format(
        consensus.getValidAfterMillis());
    String referencing = String.format("C-%s", validAfter);
    this.addReference(referencing, String.format("M-%s", validAfter), 1.0,
        consensus.getValidAfterMillis() + THREE_HOURS);
    for (DirSourceEntry dirSourceEntry :
        consensus.getDirSourceEntries().values()) {
      if (!dirSourceEntry.isLegacy()) {
        this.addReference(referencing, String.format("V-%s-%s",
            validAfter, dirSourceEntry.getIdentity()), 1.0,
            consensus.getValidAfterMillis() + THREE_HOURS);
      }
    }
    double entryWeight = 200.0
        / ((double) consensus.getStatusEntries().size());
    for (NetworkStatusEntry entry :
        consensus.getStatusEntries().values()) {
      this.addReference(referencing,
          String.format("S-%s", entry.getDescriptor()), entryWeight,
          entry.getPublishedMillis() + THREE_HOURS);
    }
  }

  private void readRelayNetworkStatusConsensusMicrodesc(
      RelayNetworkStatusConsensus consensus) {
    String validAfter = dateTimeFormat.format(
        consensus.getValidAfterMillis());
    String referencing = String.format("M-%s", validAfter);
    this.addReference(referencing, String.format("C-%s", validAfter), 1.0,
        consensus.getValidAfterMillis() + THREE_HOURS);
    double entryWeight = 200.0
        / ((double) consensus.getStatusEntries().size());
    for (NetworkStatusEntry entry :
        consensus.getStatusEntries().values()) {
      for (String digest : entry.getMicrodescriptorDigests()) {
        this.addReference(referencing, String.format("D-%s", digest),
            entryWeight, entry.getPublishedMillis() + THREE_HOURS);
      }
    }
  }

  private void readRelayNetworkStatusVote(RelayNetworkStatusVote vote) {
    String validAfter = dateTimeFormat.format(vote.getValidAfterMillis());
    String referencing = String.format("V-%s-%s", validAfter,
        vote.getIdentity());
    double entryWeight = 200.0
        / ((double) vote.getStatusEntries().size());
    for (NetworkStatusEntry entry : vote.getStatusEntries().values()) {
      this.addReference(referencing,
          String.format("S-%s", entry.getDescriptor()), entryWeight,
          entry.getPublishedMillis() + SIX_HOURS);
    }
  }

  private void readServerDescriptor(ServerDescriptor serverDescriptor) {
    String referenced = serverDescriptor.getExtraInfoDigest() == null ? ""
        : String.format("E-%s", serverDescriptor.getExtraInfoDigest());
    this.addReference(String.format("S-%s",
        serverDescriptor.getServerDescriptorDigest()), referenced, 0.01,
        serverDescriptor.getPublishedMillis() + SIX_HOURS);
  }

  private void readExtraInfoDescriptor(
      ExtraInfoDescriptor extraInfoDescriptor) {
    this.addReference(String.format("E-%s",
        extraInfoDescriptor.getExtraInfoDigest()), "", 0.005,
        extraInfoDescriptor.getPublishedMillis() + SIX_HOURS);
  }

  private void readMicrodescriptor(Microdescriptor microdesc) {
    this.addReference(
        String.format("D-%s", microdesc.getMicrodescriptorDigest()), "",
        0.0, this.currentTimeMillis + THIRTY_DAYS);
  }

  private void addReference(String referencing, String referenced,
      double weight, long expiresAfterMillis) {
    this.references.add(new Reference(referencing.toUpperCase(),
        referenced.toUpperCase(), weight, expiresAfterMillis));
  }

  private void dropStaleReferences() {
    SortedSet<Reference> recentReferences = new TreeSet<Reference>();
    for (Reference reference : this.references) {
      if (this.currentTimeMillis <= reference.expiresAfterMillis) {
        recentReferences.add(reference);
      }
    }
    this.references = recentReferences;
  }

  private void checkReferences() {
    Set<String> knownDescriptors = new HashSet<String>();
    for (Reference reference : this.references) {
      knownDescriptors.add(reference.referencing);
    }
    double totalMissingDescriptorsWeight = 0.0;
    Set<String> missingDescriptors = new TreeSet<String>();
    StringBuilder sb = new StringBuilder("Missing referenced "
        + "descriptors:");
    for (Reference reference : this.references) {
      if (reference.referenced.length() > 0
          && !knownDescriptors.contains(reference.referenced)) {
        if (!missingDescriptors.contains(reference.referenced)) {
          totalMissingDescriptorsWeight += reference.weight;
        }
        missingDescriptors.add(reference.referenced);
        sb.append(String.format("%n%s -> %s (%.4f -> %.4f)",
            reference.referencing, reference.referenced, reference.weight,
            totalMissingDescriptorsWeight));
      }
    }
    logger.info(sb.toString());
    if (totalMissingDescriptorsWeight > 0.999) {
      logger.warn("Missing too many referenced "
          + "descriptors (" + totalMissingDescriptorsWeight + ").");
    }
  }

  private void writeReferencesFile() {
    Gson gson = new Gson();
    try {
      FileWriter fw = new FileWriter(this.referencesFile);
      gson.toJson(this.references, fw);
      fw.close();
    } catch (IOException e) {
      logger.warn("Cannot write references file for next "
          + "run.", e);
    }
  }
}

