/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.net.*;
import java.text.*;
import java.util.*;
import java.util.logging.*;
import java.util.zip.*;

import org.apache.commons.codec.digest.*;
import org.apache.commons.codec.binary.*;

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
   *
   * - "consensus,<validafter>,<parsed>",
   * - "vote,<validafter>,<fingerprint>,<parsed>",
   * - "server,<published>,<relayid>,<descid>,<parsed>", or
   * - "extra,<published>,<relayid>,<descid>,<parsed>".
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
   * Should we try to download the current consensus if we don't have it?
   */
  private boolean downloadCurrentConsensus;

  /**
   * Should we try to download current votes if we don't have them?
   */
  private boolean downloadCurrentVotes;

  /**
   * Should we try to download missing server descriptors that have been
   * published within the past 24 hours?
   */
  private boolean downloadMissingServerDescriptors;

  /**
   * Should we try to download missing extra-info descriptors that have
   * been published within the past 24 hours?
   */
  private boolean downloadMissingExtraInfos;

  /**
   * Should we try to download all server descriptors from the authorities
   * once every 24 hours?
   */
  private boolean downloadAllServerDescriptors;

  /**
   * Should we try to download all extra-info descriptors from the
   * authorities once every 24 hours?
   */
  private boolean downloadAllExtraInfos;

  /**
   * Should we download zlib-compressed versions of descriptors by adding
   * ".z" to URLs?
   */
  private boolean downloadCompressed;

  /**
   * valid-after time that we expect the current consensus and votes to
   * have, formatted "yyyy-MM-dd HH:mm:ss". We only expect to find
   * consensuses and votes with this valid-after time on the directory
   * authorities. This time is initialized as the beginning of the current
   * hour.
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
  private Logger logger;

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
  private int oldMissingConsensuses = 0, oldMissingVotes = 0,
      oldMissingServerDescriptors = 0, oldMissingExtraInfoDescriptors = 0,
      newMissingConsensuses = 0, newMissingVotes = 0,
      newMissingServerDescriptors = 0, newMissingExtraInfoDescriptors = 0,
      requestedConsensuses = 0, requestedVotes = 0,
      requestedMissingServerDescriptors = 0,
      requestedAllServerDescriptors = 0,
      requestedMissingExtraInfoDescriptors = 0,
      requestedAllExtraInfoDescriptors = 0, downloadedConsensuses = 0,
      downloadedVotes = 0, downloadedMissingServerDescriptors = 0,
      downloadedAllServerDescriptors = 0,
      downloadedMissingExtraInfoDescriptors = 0,
      downloadedAllExtraInfoDescriptors = 0;

  /**
   * Initializes this class, including reading in missing descriptors from
   * <code>stats/missing-relay-descriptors</code> and the times when we
   * last downloaded all server and extra-info descriptors from
   * <code>stats/last-downloaded-all-descriptors</code>.
   */
  public RelayDescriptorDownloader(RelayDescriptorParser rdp,
      List<String> authorities, boolean downloadCurrentConsensus,
      boolean downloadCurrentVotes,
      boolean downloadMissingServerDescriptors,
      boolean downloadMissingExtraInfos,
      boolean downloadAllServerDescriptors, boolean downloadAllExtraInfos,
      boolean downloadCompressed) {

    /* Memorize argument values. */
    this.rdp = rdp;
    this.authorities = new ArrayList<String>(authorities);
    this.downloadCurrentConsensus = downloadCurrentConsensus;
    this.downloadCurrentVotes = downloadCurrentVotes;
    this.downloadMissingServerDescriptors =
        downloadMissingServerDescriptors;
    this.downloadMissingExtraInfos = downloadMissingExtraInfos;
    this.downloadAllServerDescriptors = downloadAllServerDescriptors;
    this.downloadAllExtraInfos = downloadAllExtraInfos;
    this.downloadCompressed = downloadCompressed;

    /* Shuffle list of authorities for better load balancing over time. */
    Collections.shuffle(this.authorities);

    /* Initialize logger. */
    this.logger = Logger.getLogger(
        RelayDescriptorDownloader.class.getName());

    /* Prepare cut-off times and timestamp for the missing descriptors
     * list and the list of authorities to download all server and
     * extra-info descriptors from. */
    SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    format.setTimeZone(TimeZone.getTimeZone("UTC"));
    long now = System.currentTimeMillis();
    this.currentValidAfter = format.format((now / (60L * 60L * 1000L)) *
        (60L * 60L * 1000L));
    this.descriptorCutOff = format.format(now - 24L * 60L * 60L * 1000L);
    this.currentTimestamp = format.format(now);
    this.downloadAllDescriptorsCutOff = format.format(now
        - 23L * 60L * 60L * 1000L - 30L * 60L * 1000L);

    /* Read list of missing descriptors from disk and memorize those that
     * we are interested in and that are likely to be found on the
     * directory authorities. */
    this.missingDescriptors = new TreeMap<String, String>();
    this.missingDescriptorsFile = new File(
        "stats/missing-relay-descriptors");
    if (this.missingDescriptorsFile.exists()) {
      try {
        this.logger.fine("Reading file "
            + this.missingDescriptorsFile.getAbsolutePath() + "...");
        BufferedReader br = new BufferedReader(new FileReader(
            this.missingDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (line.split(",").length > 2) {
            String published = line.split(",")[1];
            if (((line.startsWith("consensus,") ||
                line.startsWith("vote,")) &&
                this.currentValidAfter.equals(published)) ||
                ((line.startsWith("server,") ||
                line.startsWith("extra,")) &&
                this.descriptorCutOff.compareTo(published) < 0)) {
              if (!line.endsWith("NA")) {
                /* Not missing. */
              } else if (line.startsWith("consensus,")) {
                oldMissingConsensuses++;
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
            }
          } else {
            this.logger.fine("Invalid line '" + line + "' in "
                + this.missingDescriptorsFile.getAbsolutePath()
                + ". Ignoring.");
          }
        }
        br.close();
        this.logger.fine("Finished reading file "
            + this.missingDescriptorsFile.getAbsolutePath() + ".");
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Failed to read file "
            + this.missingDescriptorsFile.getAbsolutePath()
            + "! This means that we might forget to dowload relay "
            + "descriptors we are missing.", e);
      }
    }

    /* Put the current consensus on the missing list, unless we already
     * have it. */
    String consensusKey = "consensus," + this.currentValidAfter;
    if (!this.missingDescriptors.containsKey(consensusKey)) {
      this.missingDescriptors.put(consensusKey, "NA");
      this.newMissingConsensuses++;
    }

    /* Read list of directory authorities and when we last downloaded all
     * server and extra-info descriptors from them. */
    this.lastDownloadedAllDescriptors = new HashMap<String, String>();
    this.lastDownloadedAllDescriptorsFile = new File(
        "stats/last-downloaded-all-descriptors");
    if (this.lastDownloadedAllDescriptorsFile.exists()) {
      try {
        this.logger.fine("Reading file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + "...");
        BufferedReader br = new BufferedReader(new FileReader(
            this.lastDownloadedAllDescriptorsFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (line.split(",").length != 2) {
            this.logger.fine("Invalid line '" + line + "' in "
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
        this.logger.fine("Finished reading file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + ".");
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Failed to read file "
            + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
            + "! This means that we might download all server and "
            + "extra-info descriptors more often than we should.", e);
      }
    }

    /* Make a list of directory authorities that we want to download all
     * server and extra-info descriptors from. */
    this.downloadAllDescriptorsFromAuthorities = new HashSet<String>();
    for (String authority : this.authorities) {
      if (!this.lastDownloadedAllDescriptors.containsKey(authority) ||
          this.lastDownloadedAllDescriptors.get(authority).compareTo(
          this.downloadAllDescriptorsCutOff) < 0) {
        this.downloadAllDescriptorsFromAuthorities.add(authority);
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
   * "<published>,<relayid>,<descid>" to that list.
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
   * We have parsed a vote. Take this vote off the missing list and add
   * the <code>serverDescriptors</code> which are in the format
   * "<published>,<relayid>,<descid>" to that list.
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
   * Downloads missing descriptors that we think might still be available
   * on the directory authorities as well as all server and extra-info
   * descriptors once per day.
   */
  public void downloadDescriptors() {

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
          String consensusKey = "consensus," + this.currentValidAfter;
          if (this.missingDescriptors.containsKey(consensusKey) &&
              this.missingDescriptors.get(consensusKey).equals("NA")) {
            this.requestedConsensuses++;
            this.downloadedConsensuses +=
                this.downloadResourceFromAuthority(authority,
                "/tor/status-vote/current/consensus");
          }
        }

        /* Next, try to download current votes that we're missing. */
        if (downloadCurrentVotes) {
          String voteKeyPrefix = "vote," + this.currentValidAfter;
          SortedSet<String> fingerprints = new TreeSet<String>();
          for (Map.Entry<String, String> e :
              this.missingDescriptors.entrySet()) {
            if (e.getValue().equals("NA") &&
                e.getKey().startsWith(voteKeyPrefix)) {
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
         * request extra-info descriptors. */
        List<String> types = new ArrayList<String>(Arrays.asList(
            "server,extra".split(",")));
        for (String type : types) {

          /* Download all server or extra-info descriptors from this
           * authority if we haven't done so for 24 hours and if we're
           * configured to do so. */
          /* TODO Distribute downloads of all descriptors over the day for
           * different authorities. Maybe limit the number of these
           * downloads to 1 or 2 per execution. */
          if (this.downloadAllDescriptorsFromAuthorities.contains(
              authority) && ((type.equals("server") &&
              this.downloadAllServerDescriptors) ||
              (type.equals("extra") && this.downloadAllExtraInfos))) {
            int downloadedAllDescriptors =
                this.downloadResourceFromAuthority(authority, "/tor/"
                + type + "/all");
            if (type.equals("server")) {
              this.requestedAllServerDescriptors++;
              this.downloadedAllServerDescriptors +=
                  downloadedAllDescriptors;
            } else {
              this.requestedAllExtraInfoDescriptors++;
              this.downloadedAllExtraInfoDescriptors +=
                  downloadedAllDescriptors;
            }

          /* Download missing server or extra-info descriptors if we're
           * configured to do so. */
          } else if ((type.equals("server") &&
              this.downloadMissingServerDescriptors) ||
              (type.equals("extra") && this.downloadMissingExtraInfos)) {

            /* Go through the list of missing descriptors of this type
             * and combine the descriptor identifiers to a URL of up to
             * 96 descriptors that we can download at once. */
            SortedSet<String> descriptorIdentifiers =
                new TreeSet<String>();
            for (Map.Entry<String, String> e :
                this.missingDescriptors.entrySet()) {
              if (e.getValue().equals("NA") &&
                  e.getKey().startsWith(type + ",") &&
                  this.descriptorCutOff.compareTo(
                  e.getKey().split(",")[1]) < 0) {
                String descriptorIdentifier = e.getKey().split(",")[3];
                descriptorIdentifiers.add(descriptorIdentifier);
              }
            }
            StringBuilder combinedResource = null;
            int descriptorsInCombinedResource = 0,
                requestedDescriptors = 0, downloadedDescriptors = 0;
            for (String descriptorIdentifier : descriptorIdentifiers) {
              if (descriptorsInCombinedResource >= 96) {
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
                combinedResource.append("+" + descriptorIdentifier);
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
            } else {
              this.requestedMissingExtraInfoDescriptors +=
                  requestedDescriptors;
              this.downloadedMissingExtraInfoDescriptors +=
                  downloadedDescriptors;
            }
          }
        }

      /* If a download failed, stop requesting descriptors from this
       * authority and move on to the next. */
      } catch (IOException e) {
        logger.log(Level.FINE, "Failed downloading from " + authority
            + "!", e);
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
    URL u = new URL(fullUrl);
    HttpURLConnection huc = (HttpURLConnection) u.openConnection();
    huc.setRequestMethod("GET");
    huc.connect();
    int response = huc.getResponseCode();
    if (response == 200) {
      BufferedInputStream in = downloadCompressed
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
    logger.fine("Downloaded " + fullUrl + " -> " + response + " ("
        + (allData == null ? 0 : allData.length) + " bytes)");
    int receivedDescriptors = 0;
    if (allData != null) {
      if (resource.startsWith("/tor/status-vote/current/")) {
        this.rdp.parse(allData);
        receivedDescriptors = 1;
      } else if (resource.startsWith("/tor/server/") ||
          resource.startsWith("/tor/extra/")) {
        if (resource.equals("/tor/server/all")) {
          this.lastDownloadedAllDescriptors.put(authority,
              this.currentTimestamp);
        }
        String ascii = null;
        try {
          ascii = new String(allData, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
          /* No way that US-ASCII is not supported. */
        }
        int start = -1, sig = -1, end = -1;
        String startToken = resource.startsWith("/tor/server/") ?
            "router " : "extra-info ";
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
          String digest = Hex.encodeHexString(DigestUtils.sha(
              descBytes));
          this.rdp.parse(descBytes);
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
    int missingConsensuses = 0, missingVotes = 0,
        missingServerDescriptors = 0, missingExtraInfoDescriptors = 0;
    try {
      this.logger.fine("Writing file "
          + this.missingDescriptorsFile.getAbsolutePath() + "...");
      this.missingDescriptorsFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.missingDescriptorsFile));
      for (Map.Entry<String, String> e :
          this.missingDescriptors.entrySet()) {
        String key = e.getKey(), value = e.getValue();
        if (!value.equals("NA")) {
          /* Not missing. */
        } else if (key.startsWith("consensus,")) {
          missingConsensuses++;
        } else if (key.startsWith("vote,")) {
          missingVotes++;
        } else if (key.startsWith("server,")) {
          missingServerDescriptors++;
        } else if (key.startsWith("extra,")) {
          missingExtraInfoDescriptors++;
        }
        bw.write(key + "," + value + "\n");
      }
      bw.close();
      this.logger.fine("Finished writing file "
          + this.missingDescriptorsFile.getAbsolutePath() + ".");
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Failed writing "
          + this.missingDescriptorsFile.getAbsolutePath() + "!", e);
    }

    /* Write text file containing the directory authorities and when we
     * last downloaded all server and extra-info descriptors from them to
     * disk. */
    try {
      this.logger.fine("Writing file "
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
      this.logger.fine("Finished writing file "
          + this.lastDownloadedAllDescriptorsFile.getAbsolutePath()
          + ".");
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Failed writing "
          + this.lastDownloadedAllDescriptorsFile.getAbsolutePath() + "!",
          e);
    }

    /* Log statistics about this execution. */
    this.logger.info("Finished downloading relay descriptors from the "
        + "directory authorities.");
    this.logger.info("At the beginning of this execution, we were "
        + "missing " + oldMissingConsensuses + " consensus(es), "
        + oldMissingVotes + " vote(s), " + oldMissingServerDescriptors
        + " server descriptor(s), and " + oldMissingExtraInfoDescriptors
        + " extra-info descriptor(s).");
    this.logger.info("During this execution, we added "
        + this.newMissingConsensuses + " consensus(es), "
        + this.newMissingVotes + " vote(s), "
        + this.newMissingServerDescriptors + " server descriptor(s), and "
        + this.newMissingExtraInfoDescriptors + " extra-info "
        + "descriptor(s) to the missing list, some of which we also "
        + "requested and removed from the list again.");
    this.logger.info("We requested " + this.requestedConsensuses
        + " consensus(es), " + this.requestedVotes + " vote(s), "
        + this.requestedMissingServerDescriptors + " missing server "
        + "descriptor(s), " + this.requestedAllServerDescriptors
        + " times all server descriptors, "
        + this.requestedMissingExtraInfoDescriptors + " missing "
        + "extra-info descriptor(s), and "
        + this.requestedAllExtraInfoDescriptors + " times all extra-info "
        + "descriptors from the directory authorities.");
    StringBuilder sb = new StringBuilder();
    for (String authority : this.authorities) {
      sb.append(" " + authority + "="
         + this.requestsByAuthority.get(authority));
    }
    this.logger.info("We sent these numbers of requests to the directory "
        + "authorities:" + sb.toString());
    this.logger.info("We successfully downloaded "
        + this.downloadedConsensuses + " consensus(es), "
        + this.downloadedVotes + " vote(s), "
        + this.downloadedMissingServerDescriptors + " missing server "
        + "descriptor(s), " + this.downloadedAllServerDescriptors
        + " server descriptor(s) when downloading all descriptors, "
        + this.downloadedMissingExtraInfoDescriptors + " missing "
        + "extra-info descriptor(s) and "
        + this.downloadedAllExtraInfoDescriptors + " extra-info "
        + "descriptor(s) when downloading all descriptors.");
    this.logger.info("At the end of this execution, we are missing "
      + missingConsensuses + " consensus(es), " + missingVotes
      + " vote(s), " + missingServerDescriptors + " server "
      + "descriptor(s), and " + missingExtraInfoDescriptors
      + " extra-info descriptor(s), some of which we may try in the next "
      + "execution.");
  }
}

