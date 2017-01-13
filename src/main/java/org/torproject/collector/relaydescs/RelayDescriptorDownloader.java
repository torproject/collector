/* Copyright 2010--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.relaydescs;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.zip.InflaterInputStream;

/**
 * Downloads relay descriptors from the directory authorities via HTTP.
 * Keeps a list of missing descriptors that gets updated by parse results
 * from <code>RelayDescriptorParser</code> and downloads all missing
 * descriptors that have been published in the last 24 hours. Also
 * downloads all server and extra-info descriptors known to a directory
 * authority at most once a day.
 */
public class RelayDescriptorDownloader {

  /**
   * Text file containing the descriptors that we are missing and that we
   * want to download. Lines are formatted as:
   * <p>
   * - "consensus,&lt;validafter&gt;,&lt;parsed&gt;",
   * - "consensus-microdesc,&lt;validafter&gt;,&lt;parsed&gt;",
   * - "vote,&lt;validafter&gt;,&lt;fingerprint&gt;,&lt;parsed&gt;",
   * - "server,&lt;published&gt;,&lt;relayid&gt;,&lt;descid&gt;,&lt;parsed&gt;",
   * - "extra,&lt;published&gt;,&lt;relayid&gt;,&lt;descid&gt;,&lt;parsed&gt;",
   *   or
   * - "micro,&lt;validafter&gt;,&lt;relayid&gt;,&lt;descid&gt;,&lt;parsed&gt;".
   * </p>
   */
  private File missingDescriptorsFile;

  /**
   * Relay descriptors that we are missing and that we want to download
   * either in this execution or write to disk and try next time. Map keys
   * contain comma-separated values as in the missing descriptors files
   * without the "parsed" column. Map values contain the "parsed" column.
   */
  private SortedMap<String, String> missingDescriptors;

  /**
   * Map from base64 microdescriptor digests to keys in missingDescriptors
   * ("micro,&lt;validafter&gt;,&lt;relayid&gt;,&lt;descid&gt;"). We need this
   * map, because we can't learn &lt;validafter&gt; or &lt;relayid&gt; from
   * parsing microdescriptors, but we need to know &lt;validafter&gt; to store
   * microdescriptors to disk and both &lt;validafter&gt; and &lt;relayid&gt; to
   * remove microdescriptors from the missing list. There are potentially
   * many matching keys in missingDescriptors for the same microdescriptor
   * digest. Also, in rare cases relays share the same microdescriptor
   * (which is only possible if they share the same onion key), and then
   * we don't have to download their microdescriptor more than once.
   */
  private Map<String, Set<String>> microdescriptorKeys;

  /**
   * Set of microdescriptor digests that are currently missing. Used for
   * logging statistics instead of "micro,&lt;validafter&gt;,..." keys which may
   * contain the same microdescriptor digest multiple times.
   */
  private Set<String> missingMicrodescriptors;

  /**
   * Text file containing the IP addresses (and Dir ports if not 80) of
   * directory authorities and when we last downloaded all server and
   * extra-info descriptors from them, so that we can avoid downloading
   * them too often.
   */
  private File lastDownloadedAllDescriptorsFile;

  /**
   * Map of directory authorities and when we last downloaded all server
   * and extra-info descriptors from them. Map keys are IP addresses (and
   * Dir ports if not 80), map values are timestamps.
   */
  private Map<String, String> lastDownloadedAllDescriptors;

  /**
   * <code>RelayDescriptorParser</code> that we will hand over the
   * downloaded descriptors for parsing.
   */
  private RelayDescriptorParser rdp;

  /**
   * Directory authorities that we will try to download missing
   * descriptors from.
   */
  private List<String> authorities;

  /**
   * Fingerprints of directory authorities that we will use to download
   * votes without requiring a successfully downloaded consensus.
   */
  private List<String> authorityFingerprints;

  /**
   * Try to download the current consensus if we don't have it.
   */
  private boolean downloadCurrentConsensus;

  /**
   * Try to download the current microdesc consensus if we don't
   * have it.
   */
  private boolean downloadCurrentMicrodescConsensus;

  /**
   * Try to download current votes if we don't have them.
   */
  private boolean downloadCurrentVotes;

  /**
   * Try to download missing server descriptors that have been
   * published within the past 24 hours.
   */
  private boolean downloadMissingServerDescriptors;

  /**
   * Try to download missing extra-info descriptors that have
   * been published within the past 24 hours.
   */
  private boolean downloadMissingExtraInfos;

  /**
   * Try to download missing microdescriptors that have been
   * published within the past 24 hours.
   */
  private boolean downloadMissingMicrodescriptors;

  /**
   * Try to download all server descriptors from the authorities
   * once every 24 hours.
   */
  private boolean downloadAllServerDescriptors;

  /**
   * Try to download all extra-info descriptors from the
   * authorities once every 24 hours.
   */
  private boolean downloadAllExtraInfos;

  /**
   * Download zlib-compressed versions of descriptors by adding
   * ".z" to URLs.
   */
  private boolean downloadCompressed;

  /**
   * valid-after time that we expect the current consensus,
   * microdescriptor consensus, and votes to have, formatted
   * "yyyy-MM-dd HH:mm:ss". We only expect to find documents with this
   * valid-after time on the directory authorities. This time is
   * initialized as the beginning of the current hour.
   */
  private String currentValidAfter;

  /**
   * Cut-off time for missing server and extra-info descriptors, formatted
   * "yyyy-MM-dd HH:mm:ss". This time is initialized as the current system
   * time minus 24 hours.
   */
  private String descriptorCutOff;

  /**
   * Cut-off time for downloading all server and extra-info descriptors
   * from the directory authorities, formatted "yyyy-MM-dd HH:mm:ss". This
   * time is initialized as the current system time minus 23:30 hours.
   */
  private String downloadAllDescriptorsCutOff;

  /**
   * Directory authorities that we plan to download all server and
   * extra-info descriptors from in this execution.
   */
  private Set<String> downloadAllDescriptorsFromAuthorities;

  /**
   * Current timestamp that is written to the missing list for descriptors
   * that we parsed in this execution and for authorities that we
   * downloaded all server and extra-info descriptors from.
   */
  private String currentTimestamp;

  /**
   * Logger for this class.
   */
  private static final Logger logger = LoggerFactory.getLogger(
      RelayDescriptorDownloader.class);

  /**
   * Number of descriptors requested by directory authority to be included
   * in logs.
   */
  private Map<String, Integer> requestsByAuthority;

  /**
   * Counters for descriptors that we had on the missing list at the
   * beginning of the execution, that we added to the missing list,
   * that we requested, and that we successfully downloaded in this
   * execution.
   */
  private int oldMissingConsensuses = 0;

  private int oldMissingMicrodescConsensuses = 0;

  private int oldMissingVotes = 0;

  private int oldMissingServerDescriptors = 0;

  private int oldMissingExtraInfoDescriptors = 0;

  private int oldMissingMicrodescriptors = 0;

  private int newMissingConsensuses = 0;

  private int newMissingMicrodescConsensuses = 0;

  private int newMissingVotes = 0;

  private int newMissingServerDescriptors = 0;

  private int newMissingExtraInfoDescriptors = 0;

  private int newMissingMicrodescriptors = 0;

  private int requestedConsensuses = 0;

  private int requestedMicrodescConsensuses = 0;

  private int requestedVotes = 0;

  private int requestedMissingServerDescriptors = 0;

  private int requestedAllServerDescriptors = 0;

  private int requestedMissingExtraInfoDescriptors = 0;

  private int requestedAllExtraInfoDescriptors = 0;

  private int requestedMissingMicrodescriptors = 0;

  private int downloadedConsensuses = 0;

  private int downloadedMicrodescConsensuses = 0;

  private int downloadedVotes = 0;

  private int downloadedMissingServerDescriptors = 0;

  private int downloadedAllServerDescriptors = 0;

  private int downloadedMissingExtraInfoDescriptors = 0;

  private int downloadedAllExtraInfoDescriptors = 0;

  private int downloadedMissingMicrodescriptors = 0;

  /**
   * Initializes this class, including reading in missing descriptors from
   * <code>stats/missing-relay-descriptors</code> and the times when we
   * last downloaded all server and extra-info descriptors from
   * <code>stats/last-downloaded-all-descriptors</code>.
   */
  public RelayDescriptorDownloader(RelayDescriptorParser rdp,
      String[] authorities, String[] authorityFingerprints,
      boolean downloadCurrentConsensus,
      boolean downloadCurrentMicrodescConsensus,
      boolean downloadCurrentVotes,
      boolean downloadMissingServerDescriptors,
      boolean downloadMissingExtraInfos,
      boolean downloadMissingMicrodescriptors,
      boolean downloadAllServerDescriptors, boolean downloadAllExtraInfos,
      boolean downloadCompressed) {

    /* Memorize argument values. */
    this.rdp = rdp;
    this.authorities = Arrays.asList(authorities);
    this.authorityFingerprints = Arrays.asList(authorityFingerprints);
    this.downloadCurrentConsensus = downloadCurrentConsensus;
    this.downloadCurrentMicrodescConsensus =
        downloadCurrentMicrodescConsensus;
    this.downloadCurrentVotes = downloadCurrentVotes;
    this.downloadMissingServerDescriptors =
        downloadMissingServerDescriptors;
    this.downloadMissingExtraInfos = downloadMissingExtraInfos;
    this.downloadMissingMicrodescriptors =
        downloadMissingMicrodescriptors;
    this.downloadAllServerDescriptors = downloadAllServerDescriptors;
    this.downloadAllExtraInfos = downloadAllExtraInfos;
    this.downloadCompressed = downloadCompressed;

    /* Shuffle list of authorities for better load balancing over time. */
    Collections.shuffle(this.authorities);

    /* Prepare cut-off times and timestamp for the missing descriptors
     * list and the list of authorities to download all server and
     * extra-info descriptors from. */
    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    format.setTimeZone(TimeZone.getTimeZone("UTC"));
    long now = System.currentTimeMillis();
    this.currentValidAfter = format.format((now / (60L * 60L * 1000L))
        * (60L * 60L * 1000L));
    this.descriptorCutOff = format.format(now - 24L * 60L * 60L * 1000L);
    this.currentTimestamp = format.format(now);
    this.downloadAllDescriptorsCutOff = format.format(now
        - 23L * 60L * 60L * 1000L - 30L * 60L * 1000L);

    /* Read list of missing descriptors from disk and memorize those that
     * we are interested in and that are likely to be found on the
     * directory authorities. */
    this.missingDescriptors = new TreeMap<String, String>();
    this.microdescriptorKeys = new HashMap<String, Set<String>>();
    this.missingMicrodescriptors = new HashSet<String>();
    this.missingDescriptorsFile = new File(
        "stats/missing-relay-descriptors");
    if (this.missingDescriptorsFile.exists()) {
      try {
        logger.debug("Reading file "
            + this.missingDescriptorsFile.getAbsolutePath() + "...");
        BufferedReader br = new BufferedReader(new FileReader(
            this.missingDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (line.split(",").length > 2) {
            String published = line.split(",")[1];
            if (((line.startsWith("consensus,")
                || line.startsWith("consensus-microdesc,")
                || line.startsWith("vote,"))
                && this.currentValidAfter.equals(published))
                || ((line.startsWith("server,")
                || line.startsWith("extra,")
                || line.startsWith("micro,"))
                && this.descriptorCutOff.compareTo(published) < 0)) {
              if (!line.endsWith("NA")) {
                /* Not missing. */
              } else if (line.startsWith("consensus,")) {
                oldMissingConsensuses++;
              } else if (line.startsWith("consensus-microdesc,")) {
                oldMissingMicrodescConsensuses++;
              } else if (line.startsWith("vote,")) {
                oldMissingVotes++;
              } else if (line.startsWith("server,")) {
                oldMissingServerDescriptors++;
              } else if (line.startsWith("extra,")) {
                oldMissingExtraInfoDescriptors++;
              }
              int separateAt = line.lastIndexOf(",");
              this.missingDescriptors.put(line.substring(0,
                  separateAt), line.substring(separateAt + 1));
              if (line.startsWith("micro,")) {
                String microdescriptorDigest = line.split(",")[3];
                String microdescriptorKey = line.substring(0,
                    line.lastIndexOf(","));
                if (!this.microdescriptorKeys.containsKey(
                    microdescriptorDigest)) {
                  this.microdescriptorKeys.put(
                      microdescriptorDigest, new HashSet<String>());
                }
                this.microdescriptorKeys.get(microdescriptorDigest).add(
                    microdescriptorKey);
                if (line.endsWith("NA") && !this.missingMicrodescriptors
                    .contains(microdescriptorDigest)) {
                  this.missingMicrodescriptors.add(microdescriptorDigest);
                  oldMissingMicrodescriptors++;
                }
              }
            }
          } else {
            logger.debug("Invalid line '" + line + "' in "
                + this.missingDescriptorsFile.getAbsolutePath()
                + ". Ignoring.");
          }
        }
        br.close();
        logger.debug("Finished reading file "
            + this.missingDescriptorsFile.getAbsolutePath() + ".");
      } catch (IOException e) {
        logger.warn("Failed to read file "
            + this.missingDescriptorsFile.getAbsolutePath()
            + "! This means that we might forget to dowload relay "
            + "descriptors we are missing.", e);
      }
    }

    /* Read list of directory authorities and when we last downloaded all
     * server and extra-info descriptors from them. */
    this.lastDownloadedAllDescriptors = new HashMap<String, String>();
    this.lastDownloadedAllDescriptorsFile = new File(
        "stats/last-downloaded-all-descriptors");
    if (this.lastDownloadedAllDescriptorsFile.exists()) {
      try {
        logger.debug("Reading file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + "...");
        BufferedReader br = new BufferedReader(new FileReader(
            this.lastDownloadedAllDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (line.split(",").length != 2) {
            logger.debug("Invalid line '" + line + "' in "
                + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
                + ". Ignoring.");
          } else {
            String[] parts = line.split(",");
            String authority = parts[0];
            String lastDownloaded = parts[1];
            this.lastDownloadedAllDescriptors.put(authority,
                lastDownloaded);
          }
        }
        br.close();
        logger.debug("Finished reading file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + ".");
      } catch (IOException e) {
        logger.warn("Failed to read file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + "! This means that we might download all server and "
            + "extra-info descriptors more often than we should.", e);
      }
    }

    /* Make a list of at most two directory authorities that we want to
     * download all server and extra-info descriptors from. */
    this.downloadAllDescriptorsFromAuthorities = new HashSet<String>();
    for (String authority : this.authorities) {
      if (!this.lastDownloadedAllDescriptors.containsKey(authority)
          || this.lastDownloadedAllDescriptors.get(authority).compareTo(
          this.downloadAllDescriptorsCutOff) < 0) {
        this.downloadAllDescriptorsFromAuthorities.add(authority);
      }
      if (this.downloadAllDescriptorsFromAuthorities.size() >= 2) {
        break;
      }
    }

    /* Prepare statistics on this execution. */
    this.requestsByAuthority = new HashMap<String, Integer>();
    for (String authority : this.authorities) {
      this.requestsByAuthority.put(authority, 0);
    }
  }

  /**
   * We have parsed a consensus. Take this consensus off the missing list
   * and add the votes created by the given <code>authorities</code> and
   * the <code>serverDescriptors</code> which are in the format
   * "&lt;published&gt;,&lt;relayid&gt;,&lt;descid&gt;" to that list.
   */
  public void haveParsedConsensus(String validAfter,
      Set<String> authorities, Set<String> serverDescriptors) {

    /* Mark consensus as parsed. */
    if (this.currentValidAfter.equals(validAfter)) {
      String consensusKey = "consensus," + validAfter;
      this.missingDescriptors.put(consensusKey, this.currentTimestamp);

      /* Add votes to missing list. */
      for (String authority : authorities) {
        String voteKey = "vote," + validAfter + "," + authority;
        if (!this.missingDescriptors.containsKey(voteKey)) {
          this.missingDescriptors.put(voteKey, "NA");
          this.newMissingVotes++;
        }
      }
    }

    /* Add server descriptors to missing list. */
    for (String serverDescriptor : serverDescriptors) {
      String published = serverDescriptor.split(",")[0];
      if (this.descriptorCutOff.compareTo(published) < 0) {
        String serverDescriptorKey = "server," + serverDescriptor;
        if (!this.missingDescriptors.containsKey(
            serverDescriptorKey)) {
          this.missingDescriptors.put(serverDescriptorKey, "NA");
          this.newMissingServerDescriptors++;
        }
      }
    }
  }

  /**
   * We have parsed a microdesc consensus. Take this microdesc consensus off the
   * missing list and add the <code>microdescriptors</code> which are in the
   * format "&lt;validafter&gt;,&lt;relayid&gt;,&lt;descid&gt;" to that list.
   */
  public void haveParsedMicrodescConsensus(String validAfter,
      Set<String> microdescriptors) {

    /* Mark microdesc consensus as parsed. */
    if (this.currentValidAfter.equals(validAfter)) {
      String microdescConsensusKey = "consensus-microdesc," + validAfter;
      this.missingDescriptors.put(microdescConsensusKey,
          this.currentTimestamp);
    }

    /* Add microdescriptors to missing list. Exclude those that we already
     * downloaded this month. (We download each microdescriptor at least
     * once per month to keep the storage logic sane; otherwise we'd have
     * to copy microdescriptors from the earlier month to the current
     * month, and that gets messy.) */
    if (this.descriptorCutOff.compareTo(validAfter) < 0) {
      String validAfterYearMonth = validAfter.substring(0,
          "YYYY-MM".length());
      for (String microdescriptor : microdescriptors) {
        String microdescriptorKey = "micro," + microdescriptor;
        String parsed = "NA";
        String microdescriptorDigest = microdescriptor.split(",")[2];
        if (this.microdescriptorKeys.containsKey(microdescriptorDigest)) {
          for (String otherMicrodescriptorKey :
              this.microdescriptorKeys.get(microdescriptorDigest)) {
            String otherValidAfter =
                otherMicrodescriptorKey.split(",")[1];
            if (!otherValidAfter.startsWith(validAfterYearMonth)) {
              continue;
            }
            String otherParsed = this.missingDescriptors.get(
                otherMicrodescriptorKey);
            if (otherParsed != null && !otherParsed.equals("NA")) {
              parsed = otherParsed;
              break;
            }
          }
        } else {
          this.microdescriptorKeys.put(
              microdescriptorDigest, new HashSet<String>());
        }
        this.microdescriptorKeys.get(microdescriptorDigest).add(
            microdescriptorKey);
        this.missingDescriptors.put(microdescriptorKey, parsed);
        if (parsed.equals("NA")
            && !this.missingMicrodescriptors.contains(microdescriptorDigest)) {
          this.missingMicrodescriptors.add(microdescriptorDigest);
          this.newMissingMicrodescriptors++;
        }
      }
    }
  }

  /**
   * We have parsed a vote. Take this vote off the missing list and add
   * the <code>serverDescriptors</code> which are in the format
   * "&lt;published&gt;,&lt;relayid&gt;,&lt;descid&gt;" to that list.
   */
  public void haveParsedVote(String validAfter, String fingerprint,
      Set<String> serverDescriptors) {

    /* Mark vote as parsed. */
    if (this.currentValidAfter.equals(validAfter)) {
      String voteKey = "vote," + validAfter + "," + fingerprint;
      this.missingDescriptors.put(voteKey, this.currentTimestamp);
    }

    /* Add server descriptors to missing list. */
    for (String serverDescriptor : serverDescriptors) {
      String published = serverDescriptor.split(",")[0];
      if (this.descriptorCutOff.compareTo(published) < 0) {
        String serverDescriptorKey = "server," + serverDescriptor;
        if (!this.missingDescriptors.containsKey(
            serverDescriptorKey)) {
          this.missingDescriptors.put(serverDescriptorKey, "NA");
          this.newMissingServerDescriptors++;
        }
      }
    }
  }

  /**
   * We have parsed a server descriptor. Take this server descriptor off
   * the missing list and put the extra-info descriptor digest on that
   * list.
   */
  public void haveParsedServerDescriptor(String published,
      String relayIdentity, String serverDescriptorDigest,
      String extraInfoDigest) {

    /* Mark server descriptor as parsed. */
    if (this.descriptorCutOff.compareTo(published) < 0) {
      String serverDescriptorKey = "server," + published + ","
          + relayIdentity + "," + serverDescriptorDigest;
      this.missingDescriptors.put(serverDescriptorKey,
          this.currentTimestamp);

      /* Add extra-info descriptor to missing list. */
      if (extraInfoDigest != null) {
        String extraInfoKey = "extra," + published + ","
            + relayIdentity + "," + extraInfoDigest;
        if (!this.missingDescriptors.containsKey(extraInfoKey)) {
          this.missingDescriptors.put(extraInfoKey, "NA");
          this.newMissingExtraInfoDescriptors++;
        }
      }
    }
  }

  /**
   * We have parsed an extra-info descriptor. Take it off the missing
   * list.
   */
  public void haveParsedExtraInfoDescriptor(String published,
      String relayIdentity, String extraInfoDigest) {
    if (this.descriptorCutOff.compareTo(published) < 0) {
      String extraInfoKey = "extra," + published + ","
          + relayIdentity + "," + extraInfoDigest;
      this.missingDescriptors.put(extraInfoKey, this.currentTimestamp);
    }
  }

  /**
   * We have parsed a microdescriptor. Take it off the missing list.
   */
  public void haveParsedMicrodescriptor(String descriptorDigest) {
    if (this.microdescriptorKeys.containsKey(descriptorDigest)) {
      for (String microdescriptorKey :
          this.microdescriptorKeys.get(descriptorDigest)) {
        String validAfter = microdescriptorKey.split(",")[0];
        if (this.descriptorCutOff.compareTo(validAfter) < 0) {
          this.missingDescriptors.put(microdescriptorKey,
              this.currentTimestamp);
        }
      }
      this.missingMicrodescriptors.remove(descriptorDigest);
    }
  }

  /**
   * Downloads missing descriptors that we think might still be available
   * on the directory authorities as well as all server and extra-info
   * descriptors once per day.
   */
  public void downloadDescriptors() {

    /* Put the current consensus and votes on the missing list, unless we
     * already have them. */
    String consensusKey = "consensus," + this.currentValidAfter;
    if (!this.missingDescriptors.containsKey(consensusKey)) {
      this.missingDescriptors.put(consensusKey, "NA");
      this.newMissingConsensuses++;
    }
    String microdescConsensusKey = "consensus-microdesc,"
        + this.currentValidAfter;
    if (!this.missingDescriptors.containsKey(microdescConsensusKey)) {
      this.missingDescriptors.put(microdescConsensusKey, "NA");
      this.newMissingMicrodescConsensuses++;
    }
    for (String authority : authorityFingerprints) {
      String voteKey = "vote," + this.currentValidAfter + "," + authority;
      if (!this.missingDescriptors.containsKey(voteKey)) {
        this.missingDescriptors.put(voteKey, "NA");
        this.newMissingVotes++;
      }
    }

    /* Download descriptors from authorities which are in random order, so
     * that we distribute the load somewhat fairly over time. */
    for (String authority : authorities) {

      /* Make all requests to an authority in a single try block. If
       * something goes wrong with this authority, we give up on all
       * downloads and continue with the next authority. */
      /* TODO Some authorities provide very little bandwidth and could
       * slow down the entire download process. Ponder adding a timeout of
       * 3 or 5 minutes per authority to avoid getting in the way of the
       * next execution. */
      try {

        /* Start with downloading the current consensus, unless we already
         * have it. */
        if (downloadCurrentConsensus) {
          if (this.missingDescriptors.containsKey(consensusKey)
              && this.missingDescriptors.get(consensusKey).equals("NA")) {
            this.requestedConsensuses++;
            this.downloadedConsensuses +=
                this.downloadResourceFromAuthority(authority,
                "/tor/status-vote/current/consensus");
          }
        }

        /* Then try to download the microdesc consensus. */
        if (downloadCurrentMicrodescConsensus) {
          if (this.missingDescriptors.containsKey(microdescConsensusKey)
              && this.missingDescriptors.get(microdescConsensusKey)
              .equals("NA")) {
            this.requestedMicrodescConsensuses++;
            this.downloadedMicrodescConsensuses +=
                this.downloadResourceFromAuthority(authority,
                "/tor/status-vote/current/consensus-microdesc");
          }
        }

        /* Next, try to download current votes that we're missing. */
        if (downloadCurrentVotes) {
          String voteKeyPrefix = "vote," + this.currentValidAfter;
          SortedSet<String> fingerprints = new TreeSet<String>();
          for (Map.Entry<String, String> e :
              this.missingDescriptors.entrySet()) {
            if (e.getValue().equals("NA")
                && e.getKey().startsWith(voteKeyPrefix)) {
              String fingerprint = e.getKey().split(",")[2];
              fingerprints.add(fingerprint);
            }
          }
          for (String fingerprint : fingerprints) {
            this.requestedVotes++;
            this.downloadedVotes +=
                this.downloadResourceFromAuthority(authority, 
                "/tor/status-vote/current/" + fingerprint);
          }
        }

        /* Download either all server and extra-info descriptors or only
         * those that we're missing. Start with server descriptors, then
         * request extra-info descriptors. Finally, request missing
         * microdescriptors. */
        for (String type : new String[] { "server", "extra", "micro" }) {

          /* Download all server or extra-info descriptors from this
           * authority if we haven't done so for 24 hours and if we're
           * configured to do so. */
          if (this.downloadAllDescriptorsFromAuthorities.contains(
              authority) && ((type.equals("server")
              && this.downloadAllServerDescriptors)
              || (type.equals("extra") && this.downloadAllExtraInfos))) {
            int downloadedAllDescriptors =
                this.downloadResourceFromAuthority(authority, "/tor/"
                + type + "/all");
            if (type.equals("server")) {
              this.requestedAllServerDescriptors++;
              this.downloadedAllServerDescriptors +=
                  downloadedAllDescriptors;
            } else if (type.equals("extra")) {
              this.requestedAllExtraInfoDescriptors++;
              this.downloadedAllExtraInfoDescriptors +=
                  downloadedAllDescriptors;
            }

          /* Download missing server descriptors, extra-info descriptors,
           * and microdescriptors if we're configured to do so. */
          } else if ((type.equals("server")
              && this.downloadMissingServerDescriptors)
              || (type.equals("extra") && this.downloadMissingExtraInfos)
              || (type.equals("micro")
              && this.downloadMissingMicrodescriptors)) {

            /* Go through the list of missing descriptors of this type
             * and combine the descriptor identifiers to a URL of up to
             * 96 server or extra-info descriptors or 92 microdescriptors
             * that we can download at once. */
            SortedSet<String> descriptorIdentifiers =
                new TreeSet<String>();
            for (Map.Entry<String, String> e :
                this.missingDescriptors.entrySet()) {
              if (e.getValue().equals("NA")
                  && e.getKey().startsWith(type + ",")
                  && this.descriptorCutOff.compareTo(
                  e.getKey().split(",")[1]) < 0) {
                String descriptorIdentifier = e.getKey().split(",")[3];
                descriptorIdentifiers.add(descriptorIdentifier);
              }
            }
            StringBuilder combinedResource = null;
            int descriptorsInCombinedResource = 0;
            int requestedDescriptors = 0;
            int downloadedDescriptors = 0;
            int maxDescriptorsInCombinedResource =
                type.equals("micro") ? 92 : 96;
            String separator = type.equals("micro") ? "-" : "+";
            for (String descriptorIdentifier : descriptorIdentifiers) {
              if (descriptorsInCombinedResource
                  >= maxDescriptorsInCombinedResource) {
                requestedDescriptors += descriptorsInCombinedResource;
                downloadedDescriptors +=
                    this.downloadResourceFromAuthority(authority,
                    combinedResource.toString());
                combinedResource = null;
                descriptorsInCombinedResource = 0;
              }
              if (descriptorsInCombinedResource == 0) {
                combinedResource = new StringBuilder("/tor/" + type
                    + "/d/" + descriptorIdentifier);
              } else {
                combinedResource.append(separator + descriptorIdentifier);
              }
              descriptorsInCombinedResource++;
            }
            if (descriptorsInCombinedResource > 0) {
              requestedDescriptors += descriptorsInCombinedResource;
              downloadedDescriptors +=
                  this.downloadResourceFromAuthority(authority,
                  combinedResource.toString());
            }
            if (type.equals("server")) {
              this.requestedMissingServerDescriptors +=
                  requestedDescriptors;
              this.downloadedMissingServerDescriptors +=
                  downloadedDescriptors;
            } else if (type.equals("extra")) {
              this.requestedMissingExtraInfoDescriptors +=
                  requestedDescriptors;
              this.downloadedMissingExtraInfoDescriptors +=
                  downloadedDescriptors;
            } else if (type.equals("micro")) {
              this.requestedMissingMicrodescriptors +=
                  requestedDescriptors;
              this.downloadedMissingMicrodescriptors +=
                  downloadedDescriptors;
            }
          }
        }

      /* If a download failed, stop requesting descriptors from this
       * authority and move on to the next. */
      } catch (IOException e) {
        logger.debug("Failed downloading from " + authority + "!", e);
      }
    }
  }

  /**
   * Attempts to download one or more descriptors identified by a resource
   * string from a directory authority and passes the returned
   * descriptor(s) to the <code>RelayDescriptorParser</code> upon success.
   * Returns the number of descriptors contained in the reply. Throws an
   * <code>IOException</code> if something goes wrong while downloading.
   */
  private int downloadResourceFromAuthority(String authority,
      String resource) throws IOException {
    byte[] allData = null;
    this.requestsByAuthority.put(authority,
        this.requestsByAuthority.get(authority) + 1);
    /* TODO Disable compressed downloads for extra-info descriptors,
     * because zlib decompression doesn't work correctly. Figure out why
     * this is and fix it. */
    String fullUrl = "http://" + authority + resource
        + (this.downloadCompressed && !resource.startsWith("/tor/extra/")
        ? ".z" : "");
    URL url = new URL(fullUrl);
    HttpURLConnection huc = (HttpURLConnection) url.openConnection();
    huc.setRequestMethod("GET");
    huc.connect();
    int response = huc.getResponseCode();
    if (response == 200) {
      BufferedInputStream in = this.downloadCompressed
          && !resource.startsWith("/tor/extra/")
          ? new BufferedInputStream(new InflaterInputStream(
          huc.getInputStream()))
          : new BufferedInputStream(huc.getInputStream());
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      int len;
      byte[] data = new byte[1024];
      while ((len = in.read(data, 0, 1024)) >= 0) {
        baos.write(data, 0, len);
      }
      in.close();
      allData = baos.toByteArray();
    }
    logger.debug("Downloaded " + fullUrl + " -> " + response + " ("
        + (allData == null ? 0 : allData.length) + " bytes)");
    int receivedDescriptors = 0;
    if (allData != null) {
      if (resource.startsWith("/tor/status-vote/current/")) {
        this.rdp.parse(allData);
        receivedDescriptors = 1;
      } else if (resource.startsWith("/tor/server/")
          || resource.startsWith("/tor/extra/")) {
        if (resource.equals("/tor/server/all")
            || resource.equals("/tor/extra/all")) {
          this.lastDownloadedAllDescriptors.put(authority,
              this.currentTimestamp);
        }
        String ascii = null;
        try {
          ascii = new String(allData, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
          /* No way that US-ASCII is not supported. */
        }
        int start = -1;
        int sig = -1;
        int end = -1;
        String startToken = resource.startsWith("/tor/server/")
            ? "router " : "extra-info ";
        String sigToken = "\nrouter-signature\n";
        String endToken = "\n-----END SIGNATURE-----\n";
        while (end < ascii.length()) {
          start = ascii.indexOf(startToken, end);
          if (start < 0) {
            break;
          }
          sig = ascii.indexOf(sigToken, start);
          if (sig < 0) {
            break;
          }
          sig += sigToken.length();
          end = ascii.indexOf(endToken, sig);
          if (end < 0) {
            break;
          }
          end += endToken.length();
          byte[] descBytes = new byte[end - start];
          System.arraycopy(allData, start, descBytes, 0, end - start);
          this.rdp.parse(descBytes);
          receivedDescriptors++;
        }
      } else if (resource.startsWith("/tor/micro/")) {
        /* TODO We need to parse microdescriptors ourselves, rather than
         * RelayDescriptorParser, because only we know the valid-after
         * time(s) of microdesc consensus(es) containing this
         * microdescriptor.  However, this breaks functional abstraction
         * pretty badly. */
        SimpleDateFormat parseFormat =
            new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        parseFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        String ascii = null;
        try {
          ascii = new String(allData, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
          /* No way that US-ASCII is not supported. */
        }
        int start = -1;
        int end = -1;
        String startToken = "onion-key\n";
        while (end < ascii.length()) {
          start = ascii.indexOf(startToken, end);
          if (start < 0) {
            break;
          }
          end = ascii.indexOf(startToken, start + 1);
          if (end < 0) {
            end = ascii.length();
            if (end <= start) {
              break;
            }
          }
          byte[] descBytes = new byte[end - start];
          System.arraycopy(allData, start, descBytes, 0, end - start);
          String digest256Base64 = Base64.encodeBase64String(
              DigestUtils.sha256(descBytes)).replaceAll("=", "");
          if (!this.microdescriptorKeys.containsKey(digest256Base64)) {
            continue;
          }
          String digest256Hex = DigestUtils.sha256Hex(descBytes);
          for (String microdescriptorKey :
              this.microdescriptorKeys.get(digest256Base64)) {
            String validAfterTime = microdescriptorKey.split(",")[1];
            try {
              long validAfter =
                  parseFormat.parse(validAfterTime).getTime();
              this.rdp.storeMicrodescriptor(descBytes, digest256Hex,
                  digest256Base64, validAfter);
            } catch (ParseException e) {
              logger.warn("Could not parse "
                  + "valid-after time '" + validAfterTime + "' in "
                  + "microdescriptor key. Not storing microdescriptor.",
                  e);
            }
          }
          receivedDescriptors++;
        }
      }
    }
    return receivedDescriptors;
  }

  /**
   * Writes status files to disk and logs statistics about downloading
   * relay descriptors in this execution.
   */
  public void writeFile() {

    /* Write missing descriptors file to disk. */
    int missingConsensuses = 0;
    int missingMicrodescConsensuses = 0;
    int missingVotes = 0;
    int missingServerDescriptors = 0;
    int missingExtraInfoDescriptors = 0;
    try {
      logger.debug("Writing file "
          + this.missingDescriptorsFile.getAbsolutePath() + "...");
      this.missingDescriptorsFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.missingDescriptorsFile));
      for (Map.Entry<String, String> e :
          this.missingDescriptors.entrySet()) {
        String key = e.getKey();
        String value = e.getValue();
        if (!value.equals("NA")) {
          /* Not missing. */
        } else if (key.startsWith("consensus,")) {
          missingConsensuses++;
        } else if (key.startsWith("consensus-microdesc,")) {
          missingMicrodescConsensuses++;
        } else if (key.startsWith("vote,")) {
          missingVotes++;
        } else if (key.startsWith("server,")) {
          missingServerDescriptors++;
        } else if (key.startsWith("extra,")) {
          missingExtraInfoDescriptors++;
        } else if (key.startsWith("micro,")) {
          /* We're counting missing microdescriptors below. */
        }
        bw.write(key + "," + value + "\n");
      }
      bw.close();
      logger.debug("Finished writing file "
          + this.missingDescriptorsFile.getAbsolutePath() + ".");
    } catch (IOException e) {
      logger.warn("Failed writing "
          + this.missingDescriptorsFile.getAbsolutePath() + "!", e);
    }

    /* Write text file containing the directory authorities and when we
     * last downloaded all server and extra-info descriptors from them to
     * disk. */
    try {
      logger.debug("Writing file "
          + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
          + "...");
      this.lastDownloadedAllDescriptorsFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.lastDownloadedAllDescriptorsFile));
      for (Map.Entry<String, String> e :
          this.lastDownloadedAllDescriptors.entrySet()) {
        String authority = e.getKey();
        String lastDownloaded = e.getValue();
        bw.write(authority + "," + lastDownloaded + "\n");
      }
      bw.close();
      logger.debug("Finished writing file "
          + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
          + ".");
    } catch (IOException e) {
      logger.warn("Failed writing "
          + this.lastDownloadedAllDescriptorsFile.getAbsolutePath() + "!",
          e);
    }

    /* Log statistics about this execution. */
    logger.info("Finished downloading relay descriptors from the "
        + "directory authorities.");
    logger.info("At the beginning of this execution, we were "
        + "missing " + oldMissingConsensuses + " consensus(es), "
        + oldMissingMicrodescConsensuses + " microdesc consensus(es), "
        + oldMissingVotes + " vote(s), " + oldMissingServerDescriptors
        + " server descriptor(s), " + oldMissingExtraInfoDescriptors
        + " extra-info descriptor(s), and " + oldMissingMicrodescriptors
        + " microdescriptor(s).");
    logger.info("During this execution, we added "
        + this.newMissingConsensuses + " consensus(es), "
        + this.newMissingMicrodescConsensuses
        + " microdesc consensus(es), " + this.newMissingVotes
        + " vote(s), " + this.newMissingServerDescriptors
        + " server descriptor(s), " + this.newMissingExtraInfoDescriptors
        + " extra-info descriptor(s), and "
        + this.newMissingMicrodescriptors + " microdescriptor(s) to the "
        + "missing list, some of which we also "
        + "requested and removed from the list again.");
    logger.info("We requested " + this.requestedConsensuses
        + " consensus(es), " + this.requestedMicrodescConsensuses
        + " microdesc consensus(es), " + this.requestedVotes
        + " vote(s), " + this.requestedMissingServerDescriptors
        + " missing server descriptor(s), "
        + this.requestedAllServerDescriptors
        + " times all server descriptors, "
        + this.requestedMissingExtraInfoDescriptors + " missing "
        + "extra-info descriptor(s), "
        + this.requestedAllExtraInfoDescriptors + " times all extra-info "
        + "descriptors, and " + this.requestedMissingMicrodescriptors
        + " missing microdescriptor(s) from the directory authorities.");
    StringBuilder sb = new StringBuilder();
    for (String authority : this.authorities) {
      sb.append(" " + authority + "="
          + this.requestsByAuthority.get(authority));
    }
    logger.info("We sent these numbers of requests to the directory "
        + "authorities:" + sb.toString());
    logger.info("We successfully downloaded "
        + this.downloadedConsensuses + " consensus(es), "
        + this.downloadedMicrodescConsensuses
        + " microdesc consensus(es), " + this.downloadedVotes
        + " vote(s), " + this.downloadedMissingServerDescriptors
        + " missing server descriptor(s), "
        + this.downloadedAllServerDescriptors
        + " server descriptor(s) when downloading all descriptors, "
        + this.downloadedMissingExtraInfoDescriptors + " missing "
        + "extra-info descriptor(s), "
        + this.downloadedAllExtraInfoDescriptors + " extra-info "
        + "descriptor(s) when downloading all descriptors, and "
        + this.downloadedMissingMicrodescriptors
        + " missing microdescriptor(s).");
    logger.info("At the end of this execution, we are missing "
        + missingConsensuses + " consensus(es), "
        + missingMicrodescConsensuses + " microdesc consensus(es), "
        + missingVotes + " vote(s), " + missingServerDescriptors
        + " server descriptor(s), " + missingExtraInfoDescriptors
        + " extra-info descriptor(s), and "
        + this.missingMicrodescriptors.size()
        + " microdescriptor(s), some of which we may try in the next "
        + "execution.");
  }
}

