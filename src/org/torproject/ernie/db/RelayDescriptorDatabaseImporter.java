/* Copyright 2010 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import java.util.logging.*;
import org.postgresql.util.*;

/**
 * Parse directory data.
 */

public final class RelayDescriptorDatabaseImporter {

  /**
   * How many records to commit with each database transaction.
   */
  private final long autoCommitCount = 500;

  /**
   * Keep track of the number of records committed before each transaction
   */
  private int rdsCount = 0;
  private int resCount = 0;
  private int rhsCount = 0;
  private int rrsCount = 0;
  private int rcsCount = 0;
  private int rvsCount = 0;
  private int rbsCount = 0;
  private int rqsCount = 0;

  /**
   * Relay descriptor database connection.
   */
  private Connection conn;

  /**
   * Prepared statement to check whether any network status consensus
   * entries matching a given valid-after time have been imported into the
   * database before.
   */
  private PreparedStatement psSs;

  /**
   * Prepared statement to check whether a given network status consensus
   * entry has been imported into the database before.
   */
  private PreparedStatement psRs;

  /**
   * Prepared statement to check whether a given extra-info descriptor has
   * been imported into the database before.
   */
  private PreparedStatement psEs;

  /**
   * Prepared statement to check whether the bandwidth history of an
   * extra-info descriptor has been imported into the database before.
   */
  private PreparedStatement psHs;

  /**
   * Prepared statement to check whether a given server descriptor has
   * been imported into the database before.
   */
  private PreparedStatement psDs;

  /**
   * Prepared statement to check whether a given network status consensus
   * has been imported into the database before.
   */
  private PreparedStatement psCs;

  /**
   * Prepared statement to check whether a given network status vote has
   * been imported into the database before.
   */
  private PreparedStatement psVs;

  /**
   * Prepared statement to check whether a given conn-bi-direct stats
   * string has been imported into the database before.
   */
  private PreparedStatement psBs;

  /**
   * Prepared statement to check whether a given dirreq stats string has
   * been imported into the database before.
   */
  private PreparedStatement psQs;

  /**
   * Set of dates that have been inserted into the database for being
   * included in the next refresh run.
   */
  private Set<Long> scheduledUpdates;

  /**
   * Prepared statement to insert a date into the database that shall be
   * included in the next refresh run.
   */
  private PreparedStatement psU;

  /**
   * Prepared statement to insert a network status consensus entry into
   * the database.
   */
  private PreparedStatement psR;

  /**
   * Prepared statement to insert a server descriptor into the database.
   */
  private PreparedStatement psD;

  /**
   * Prepared statement to insert an extra-info descriptor into the
   * database.
   */
  private PreparedStatement psE;

  /**
   * Prepared statement to insert the bandwidth history of an extra-info
   * descriptor into the database.
   */
  private PreparedStatement psH;

  /**
   * Prepared statement to insert a network status consensus into the
   * database.
   */
  private PreparedStatement psC;

  /**
   * Prepared statement to insert a network status vote into the
   * database.
   */
  private PreparedStatement psV;

  /**
   * Prepared statement to insert a conn-bi-direct stats string into the
   * database.
   */
  private PreparedStatement psB;

  /**
   * Prepared statement to insert a given dirreq stats string into the
   * database.
   */
  private PreparedStatement psQ;

  /**
   * Logger for this class.
   */
  private Logger logger;

  /**
   * Directory for writing raw import files.
   */
  private String rawFilesDirectory;

  /**
   * Raw import file containing status entries.
   */
  private BufferedWriter statusentryOut;

  /**
   * Raw import file containing server descriptors.
   */
  private BufferedWriter descriptorOut;

  /**
   * Raw import file containing extra-info descriptors.
   */
  private BufferedWriter extrainfoOut;

  /**
   * Raw import file containing bandwidth histories.
   */
  private BufferedWriter bwhistOut;

  /**
   * Raw import file containing consensuses.
   */
  private BufferedWriter consensusOut;

  /**
   * Raw import file containing votes.
   */
  private BufferedWriter voteOut;

  /**
   * Raw import file containing conn-bi-direct stats strings.
   */
  private BufferedWriter connBiDirectOut;

  /**
   * Raw import file containing dirreq stats.
   */
  private BufferedWriter dirReqOut;

  /**
   * Date format to parse timestamps.
   */
  private SimpleDateFormat dateTimeFormat;

  /**
   * The last valid-after time for which we checked whether they have been
   * any network status entries in the database.
   */
  private long lastCheckedStatusEntries;

  /**
   * Set of fingerprints that we imported for the valid-after time in
   * <code>lastCheckedStatusEntries</code>.
   */
  private Set<String> insertedStatusEntries;

  /**
   * Flag that tells us whether we need to check whether a network status
   * entry is already contained in the database or not.
   */
  private boolean separateStatusEntryCheckNecessary;

  /**
   * Initialize database importer by connecting to the database and
   * preparing statements.
   */
  public RelayDescriptorDatabaseImporter(String connectionURL,
      String rawFilesDirectory) {

    /* Initialize logger. */
    this.logger = Logger.getLogger(
        RelayDescriptorDatabaseImporter.class.getName());

    if (connectionURL != null) {
      try {
        /* Connect to database. */
        this.conn = DriverManager.getConnection(connectionURL);

        /* Turn autocommit off */
        this.conn.setAutoCommit(false);

        /* Prepare statements. */
        this.psSs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM statusentry WHERE validafter = ?");
        this.psRs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM statusentry WHERE validafter = ? AND descriptor = ?");
        this.psDs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM descriptor WHERE descriptor = ?");
        this.psEs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM extrainfo WHERE extrainfo = ?");
        this.psHs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM bwhist WHERE extrainfo = ?");
        this.psCs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM consensus WHERE validafter = ?");
        this.psVs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM vote WHERE validafter = ? AND dirsource = ?");
        this.psBs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM connbidirect WHERE source = ? AND statsend = ?");
        this.psQs = conn.prepareStatement("SELECT COUNT(*) "
            + "FROM dirreq_stats WHERE source = ? AND statsend = ?");
        this.psR = conn.prepareStatement("INSERT INTO statusentry "
            + "(validafter, nickname, fingerprint, descriptor, "
            + "published, address, orport, dirport, isauthority, "
            + "isbadexit, isbaddirectory, isexit, isfast, isguard, "
            + "ishsdir, isnamed, isstable, isrunning, isunnamed, "
            + "isvalid, isv2dir, isv3dir, version, bandwidth, ports, "
            + "rawdesc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            + "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        this.psD = conn.prepareStatement("INSERT INTO descriptor "
            + "(descriptor, nickname, address, orport, dirport, "
            + "fingerprint, bandwidthavg, bandwidthburst, "
            + "bandwidthobserved, platform, published, uptime, "
            + "extrainfo, rawdesc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            + "?, ?, ?, ?)");
        this.psE = conn.prepareStatement("INSERT INTO extrainfo "
            + "(extrainfo, nickname, fingerprint, published, rawdesc) "
            + "VALUES (?, ?, ?, ?, ?)");
        this.psH = conn.prepareStatement("INSERT INTO bwhist "
            + "(fingerprint, extrainfo, intervalend, read, written, "
            + "dirread, dirwritten) VALUES (?, ?, ?, ?, ?, ?, ?)");
        this.psC = conn.prepareStatement("INSERT INTO consensus "
            + "(validafter, rawdesc) VALUES (?, ?)");
        this.psV = conn.prepareStatement("INSERT INTO vote "
            + "(validafter, dirsource, rawdesc) VALUES (?, ?, ?)");
        this.psB = conn.prepareStatement("INSERT INTO connbidirect "
            + "(source, statsend, seconds, belownum, readnum, writenum, "
            + "bothnum) VALUES (?, ?, ?, ?, ?, ?, ?)");
        this.psQ = conn.prepareStatement("INSERT INTO dirreq_stats "
            + "(source, statsend, seconds, country, requests) VALUES "
            + "(?, ?, ?, ?, ?)");
        this.psU = conn.prepareStatement("INSERT INTO scheduled_updates "
            + "(date) VALUES (?)");
        this.scheduledUpdates = new HashSet<Long>();
      } catch (SQLException e) {
        this.logger.log(Level.WARNING, "Could not connect to database or "
            + "prepare statements.", e);
      }

      /* Initialize set of fingerprints to remember which status entries
       * we already imported. */
      this.insertedStatusEntries = new HashSet<String>();
    }

    /* Remember where we want to write raw import files. */
    this.rawFilesDirectory = rawFilesDirectory;

    /* Initialize date format, so that we can format timestamps. */
    this.dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    this.dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  private void addDateToScheduledUpdates(long timestamp)
      throws SQLException {
    long dateMillis = 0L;
    try {
      dateMillis = this.dateTimeFormat.parse(
          this.dateTimeFormat.format(timestamp).substring(0, 10)
          + " 00:00:00").getTime();
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Internal parsing error.", e);
      return;
    }
    if (!this.scheduledUpdates.contains(dateMillis)) {
      this.psU.setDate(1, new java.sql.Date(dateMillis));
      this.psU.execute();
      this.scheduledUpdates.add(dateMillis);
    }
  }

  /**
   * Insert network status consensus entry into database.
   */
  public void addStatusEntry(long validAfter, String nickname,
      String fingerprint, String descriptor, long published,
      String address, long orPort, long dirPort,
      SortedSet<String> flags, String version, long bandwidth,
      String ports, byte[] rawDescriptor) {
    try {
      if (this.psSs != null && this.psRs != null && this.psR != null) {
        this.addDateToScheduledUpdates(validAfter);
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Timestamp validAfterTimestamp = new Timestamp(validAfter);
        if (lastCheckedStatusEntries != validAfter) {
          this.psSs.setTimestamp(1, validAfterTimestamp, cal);
          ResultSet rs = psSs.executeQuery();
          rs.next();
          if (rs.getInt(1) == 0) {
            separateStatusEntryCheckNecessary = false;
            insertedStatusEntries.clear();
          } else {
            separateStatusEntryCheckNecessary = true;
          }
          rs.close();
          lastCheckedStatusEntries = validAfter;
        }
        boolean alreadyContained = false;
        if (separateStatusEntryCheckNecessary ||
            insertedStatusEntries.contains(fingerprint)) {
          this.psRs.setTimestamp(1, validAfterTimestamp, cal);
          this.psRs.setString(2, descriptor);
          ResultSet rs = psRs.executeQuery();
          rs.next();
          if (rs.getInt(1) > 0) {
            alreadyContained = true;
          }
          rs.close();
        } else {
          insertedStatusEntries.add(fingerprint);
        }
        if (!alreadyContained) {
          this.psR.clearParameters();
          this.psR.setTimestamp(1, validAfterTimestamp, cal);
          this.psR.setString(2, nickname);
          this.psR.setString(3, fingerprint);
          this.psR.setString(4, descriptor);
          this.psR.setTimestamp(5, new Timestamp(published), cal);
          this.psR.setString(6, address);
          this.psR.setLong(7, orPort);
          this.psR.setLong(8, dirPort);
          this.psR.setBoolean(9, flags.contains("Authority"));
          this.psR.setBoolean(10, flags.contains("BadExit"));
          this.psR.setBoolean(11, flags.contains("BadDirectory"));
          this.psR.setBoolean(12, flags.contains("Exit"));
          this.psR.setBoolean(13, flags.contains("Fast"));
          this.psR.setBoolean(14, flags.contains("Guard"));
          this.psR.setBoolean(15, flags.contains("HSDir"));
          this.psR.setBoolean(16, flags.contains("Named"));
          this.psR.setBoolean(17, flags.contains("Stable"));
          this.psR.setBoolean(18, flags.contains("Running"));
          this.psR.setBoolean(19, flags.contains("Unnamed"));
          this.psR.setBoolean(20, flags.contains("Valid"));
          this.psR.setBoolean(21, flags.contains("V2Dir"));
          this.psR.setBoolean(22, flags.contains("V3Dir"));
          this.psR.setString(23, version);
          this.psR.setLong(24, bandwidth);
          this.psR.setString(25, ports);
          this.psR.setBytes(26, rawDescriptor);
          this.psR.executeUpdate();
          rrsCount++;
          if (rrsCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      }
      if (this.rawFilesDirectory != null) {
        if (this.statusentryOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.statusentryOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/statusentry.sql"));
          this.statusentryOut.write(" COPY statusentry (validafter, "
              + "nickname, fingerprint, descriptor, published, address, "
              + "orport, dirport, isauthority, isbadExit, "
              + "isbaddirectory, isexit, isfast, isguard, ishsdir, "
              + "isnamed, isstable, isrunning, isunnamed, isvalid, "
              + "isv2dir, isv3dir, version, bandwidth, ports, rawdesc) "
              + "FROM stdin;\n");
        }
        this.statusentryOut.write(
            this.dateTimeFormat.format(validAfter) + "\t" + nickname
            + "\t" + fingerprint.toLowerCase() + "\t"
            + descriptor.toLowerCase() + "\t"
            + this.dateTimeFormat.format(published) + "\t" + address
            + "\t" + orPort + "\t" + dirPort + "\t"
            + (flags.contains("Authority") ? "t" : "f") + "\t"
            + (flags.contains("BadExit") ? "t" : "f") + "\t"
            + (flags.contains("BadDirectory") ? "t" : "f") + "\t"
            + (flags.contains("Exit") ? "t" : "f") + "\t"
            + (flags.contains("Fast") ? "t" : "f") + "\t"
            + (flags.contains("Guard") ? "t" : "f") + "\t"
            + (flags.contains("HSDir") ? "t" : "f") + "\t"
            + (flags.contains("Named") ? "t" : "f") + "\t"
            + (flags.contains("Stable") ? "t" : "f") + "\t"
            + (flags.contains("Running") ? "t" : "f") + "\t"
            + (flags.contains("Unnamed") ? "t" : "f") + "\t"
            + (flags.contains("Valid") ? "t" : "f") + "\t"
            + (flags.contains("V2Dir") ? "t" : "f") + "\t"
            + (flags.contains("V3Dir") ? "t" : "f") + "\t"
            + (version != null ? version : "\\N") + "\t"
            + (bandwidth >= 0 ? bandwidth : "\\N") + "\t"
            + (ports != null ? ports : "\\N") + "\t");
        this.statusentryOut.write(PGbytea.toPGString(rawDescriptor).
            replaceAll("\\\\", "\\\\\\\\") + "\n");
      }
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add network status "
          + "consensus entry.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write network status "
          + "consensus entry to raw database import file.", e);
    }
  }

  /**
   * Insert server descriptor into database.
   */
  public void addServerDescriptor(String descriptor, String nickname,
      String address, int orPort, int dirPort, String relayIdentifier,
      long bandwidthAvg, long bandwidthBurst, long bandwidthObserved,
      String platform, long published, long uptime,
      String extraInfoDigest, byte[] rawDescriptor) {
    try {
      if (this.psDs != null && this.psD != null) {
        this.addDateToScheduledUpdates(published);
        this.addDateToScheduledUpdates(
            published + 24L * 60L * 60L * 1000L);
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        this.psDs.setString(1, descriptor);
        ResultSet rs = psDs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          this.psD.clearParameters();
          this.psD.setString(1, descriptor);
          this.psD.setString(2, nickname);
          this.psD.setString(3, address);
          this.psD.setInt(4, orPort);
          this.psD.setInt(5, dirPort);
          this.psD.setString(6, relayIdentifier);
          this.psD.setLong(7, bandwidthAvg);
          this.psD.setLong(8, bandwidthBurst);
          this.psD.setLong(9, bandwidthObserved);
          this.psD.setString(10, new String(platform.getBytes(),
              "US-ASCII"));
          this.psD.setTimestamp(11, new Timestamp(published), cal);
          this.psD.setLong(12, uptime);
          this.psD.setString(13, extraInfoDigest);
          this.psD.setBytes(14, rawDescriptor);
          this.psD.executeUpdate();
          rdsCount++;
          if (rdsCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      }
      if (this.rawFilesDirectory != null) {
        if (this.descriptorOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.descriptorOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/descriptor.sql"));
          this.descriptorOut.write(" COPY descriptor (descriptor, "
              + "nickname, address, orport, dirport, fingerprint, "
              + "bandwidthavg, bandwidthburst, bandwidthobserved, "
              + "platform, published, uptime, extrainfo, rawdesc) FROM "
              + "stdin;\n");
        }
        this.descriptorOut.write(descriptor.toLowerCase() + "\t"
            + nickname + "\t" + address + "\t" + orPort + "\t" + dirPort
            + "\t" + relayIdentifier + "\t" + bandwidthAvg + "\t"
            + bandwidthBurst + "\t" + bandwidthObserved + "\t"
            + (platform != null && platform.length() > 0
            ? new String(platform.getBytes(), "US-ASCII") : "\\N")
            + "\t" + this.dateTimeFormat.format(published) + "\t"
            + (uptime >= 0 ? uptime : "\\N") + "\t"
            + (extraInfoDigest != null ? extraInfoDigest : "\\N")
            + "\t");
        this.descriptorOut.write(PGbytea.toPGString(rawDescriptor).
            replaceAll("\\\\", "\\\\\\\\") + "\n");
      }
    } catch (UnsupportedEncodingException e) {
      this.logger.log(Level.WARNING, "Could not add server descriptor.",
          e);
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add server descriptor.",
          e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write server descriptor "
          + "to raw database import file.", e);
    }
  }

  /**
   * Insert extra-info descriptor into database.
   */
  public void addExtraInfoDescriptor(String extraInfoDigest,
      String nickname, String fingerprint, long published,
      byte[] rawDescriptor, SortedMap<String, String> bandwidthHistory) {
    try {
      Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
      if (this.psEs != null && this.psE != null) {
        this.psEs.setString(1, extraInfoDigest);
        ResultSet rs = psEs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          this.psE.clearParameters();
          this.psE.setString(1, extraInfoDigest);
          this.psE.setString(2, nickname);
          this.psE.setString(3, fingerprint);
          this.psE.setTimestamp(4, new Timestamp(published), cal);
          this.psE.setBytes(5, rawDescriptor);
          this.psE.executeUpdate();
          resCount++;
          if (resCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      }
      if ((this.psHs != null && this.psH != null) ||
          this.rawFilesDirectory != null) {
        boolean addToDatabase = false;
        if (psHs != null && this.psH != null) {
          this.psHs.setString(1, extraInfoDigest);
          ResultSet rs = this.psHs.executeQuery();
          rs.next();
          if (rs.getInt(1) == 0) {
            addToDatabase = true;
          }
        }
        if (addToDatabase || this.rawFilesDirectory != null) {
          String lastIntervalEnd = null;
          List<String> bandwidthHistoryValues = new ArrayList<String>();
          bandwidthHistoryValues.addAll(bandwidthHistory.values());
          bandwidthHistoryValues.add("EOL");
          String readBytes = null, writtenBytes = null,
              dirReadBytes = null, dirWrittenBytes = null;
          for (String bandwidthHistoryValue : bandwidthHistoryValues) {
            String[] entryParts = bandwidthHistoryValue.split(",");
            String intervalEnd = entryParts[0];
            if ((intervalEnd.equals("EOL") ||
                !intervalEnd.equals(lastIntervalEnd)) &&
                lastIntervalEnd != null) {
              if (addToDatabase) {
                this.psH.clearParameters();
                this.psH.setString(1, fingerprint);
                this.psH.setString(2, extraInfoDigest);
                try {
                  this.psH.setTimestamp(3, new Timestamp(Long.parseLong(
                      lastIntervalEnd)), cal);
                  if (readBytes != null) {
                    this.psH.setLong(4, Long.parseLong(readBytes));
                  } else {
                    this.psH.setNull(4, Types.BIGINT);
                  }
                  if (writtenBytes != null) {
                    this.psH.setLong(5, Long.parseLong(writtenBytes));
                  } else {
                    this.psH.setNull(5, Types.BIGINT);
                  }
                  if (dirReadBytes != null) {
                    this.psH.setLong(6, Long.parseLong(dirReadBytes));
                  } else {
                    this.psH.setNull(6, Types.BIGINT);
                  }
                  if (dirWrittenBytes != null) {
                    this.psH.setLong(7, Long.parseLong(dirWrittenBytes));
                  } else {
                    this.psH.setNull(7, Types.BIGINT);
                  }
                } catch (NumberFormatException e) {
                  break;
                }
                this.psH.executeUpdate();
              }
              if (this.rawFilesDirectory != null) {
                if (this.bwhistOut == null) {
                  new File(rawFilesDirectory).mkdirs();
                  this.bwhistOut = new BufferedWriter(new FileWriter(
                      rawFilesDirectory + "/bwhist.sql"));
                  this.bwhistOut.write(" COPY bwhist (fingerprint, "
                      + "extrainfo, intervalend, read, written, dirread, "
                      + "dirwritten) FROM stdin;\n");
                }
                String extraInfo = extraInfoDigest.toLowerCase();
                String intervalEndString = this.dateTimeFormat.format(
                    Long.parseLong(lastIntervalEnd));
                this.bwhistOut.write(fingerprint.toLowerCase() + "\t"
                    + extraInfo + "\t" + intervalEndString + "\t"
                    + (readBytes != null ? readBytes : "\\N") + "\t"
                    + (writtenBytes != null ? writtenBytes : "\\N")
                    + "\t" + (dirReadBytes != null ? dirReadBytes
                    : "\\N") + "\t" + (dirWrittenBytes != null
                    ? dirWrittenBytes : "\\N") + "\n");
              }
              readBytes = writtenBytes = dirReadBytes = dirWrittenBytes =
                  null;
            }
            if (intervalEnd.equals("EOL")) {
              break;
            }
            lastIntervalEnd = intervalEnd;
            String type = entryParts[1];
            String bytes = entryParts[2];
            if (type.equals("read-history")) {
              readBytes = bytes;
            } else if (type.equals("write-history")) {
              writtenBytes = bytes;
            } else if (type.equals("dirreq-read-history")) {
              dirReadBytes = bytes;
            } else if (type.equals("dirreq-write-history")) {
              dirWrittenBytes = bytes;
            }
          }
          if (addToDatabase) {
            rhsCount++;
            if (rhsCount % autoCommitCount == 0)  {
              this.conn.commit();
            }
          }
        }
      }
      if (this.rawFilesDirectory != null) {
        if (this.extrainfoOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.extrainfoOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/extrainfo.sql"));
          this.extrainfoOut.write(" COPY extrainfo (extrainfo, nickname, "
              + "fingerprint, published, rawdesc) FROM stdin;\n");
        }
        this.extrainfoOut.write(extraInfoDigest.toLowerCase() + "\t"
            + nickname + "\t" + fingerprint.toLowerCase() + "\t"
            + this.dateTimeFormat.format(published) + "\t");
        this.extrainfoOut.write(PGbytea.toPGString(rawDescriptor).
            replaceAll("\\\\", "\\\\\\\\") + "\n");
      }
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add extra-info "
          + "descriptor.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write extra-info "
          + "descriptor to raw database import file.", e);
    }
  }

  /**
   * Insert network status consensus into database.
   */
  public void addConsensus(long validAfter, byte[] rawDescriptor) {
    try {
      if (this.psCs != null && this.psC != null) {
        this.addDateToScheduledUpdates(validAfter);
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Timestamp validAfterTimestamp = new Timestamp(validAfter);
        this.psCs.setTimestamp(1, validAfterTimestamp, cal);
        ResultSet rs = psCs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          this.psC.clearParameters();
          this.psC.setTimestamp(1, validAfterTimestamp, cal);
          this.psC.setBytes(2, rawDescriptor);
          this.psC.executeUpdate();
          rcsCount++;
          if (rcsCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      }
      if (this.rawFilesDirectory != null) {
        if (this.consensusOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.consensusOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/consensus.sql"));
          this.consensusOut.write(" COPY consensus (validafter, rawdesc) "
              + "FROM stdin;\n");
        }
        String validAfterString = this.dateTimeFormat.format(validAfter);
        this.consensusOut.write(validAfterString + "\t");
        this.consensusOut.write(PGbytea.toPGString(rawDescriptor).
            replaceAll("\\\\", "\\\\\\\\") + "\n");
      }
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add network status "
          + "consensus.", e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write network status "
          + "consensus to raw database import file.", e);
    }
  }

  /**
   * Insert network status vote into database.
   */
  public void addVote(long validAfter, String dirSource,
      byte[] rawDescriptor) {
    try {
      if (this.psVs != null && this.psV != null) {
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Timestamp validAfterTimestamp = new Timestamp(validAfter);
        this.psVs.setTimestamp(1, validAfterTimestamp, cal);
        this.psVs.setString(2, dirSource);
        ResultSet rs = psVs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          this.psV.clearParameters();
          this.psV.setTimestamp(1, validAfterTimestamp, cal);
          this.psV.setString(2, dirSource);
          this.psV.setBytes(3, rawDescriptor);
          this.psV.executeUpdate();
          rvsCount++;
          if (rvsCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      }
      if (this.rawFilesDirectory != null) {
        if (this.voteOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.voteOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/vote.sql"));
          this.voteOut.write(" COPY vote (validafter, dirsource, "
              + "rawdesc) FROM stdin;\n");
        }
        String validAfterString = this.dateTimeFormat.format(validAfter);
        this.voteOut.write(validAfterString + "\t" + dirSource + "\t");
        this.voteOut.write(PGbytea.toPGString(rawDescriptor).
            replaceAll("\\\\", "\\\\\\\\") + "\n");
      }
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add network status vote.",
          e);
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not write network status "
          + "vote to raw database import file.", e);
    }
  }

  /**
   * Insert a conn-bi-direct stats string into the database.
   */
  public void addConnBiDirect(String source, String statsEnd,
      long seconds, long below, long read, long write, long both) {
    long statsEndTime = 0L;
    try {
      statsEndTime = this.dateTimeFormat.parse(statsEnd).getTime();
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not add conn-bi-direct "
          + "stats string with interval ending '" + statsEnd + "'.", e);
      return;
    }
    if (this.psBs != null && this.psB != null) {
      try {
        this.addDateToScheduledUpdates(statsEndTime);
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Timestamp statsEndTimestamp = new Timestamp(statsEndTime);
        this.psBs.setString(1, source);
        this.psBs.setTimestamp(2, statsEndTimestamp, cal);
        ResultSet rs = psBs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          this.psB.clearParameters();
          this.psB.setString(1, source);
          this.psB.setTimestamp(2, statsEndTimestamp, cal);
          this.psB.setLong(3, seconds);
          this.psB.setLong(4, below);
          this.psB.setLong(5, read);
          this.psB.setLong(6, write);
          this.psB.setLong(7, both);
          this.psB.executeUpdate();
          rbsCount++;
          if (rbsCount % autoCommitCount == 0)  {
            this.conn.commit();
          }
        }
      } catch (SQLException e) {
        this.logger.log(Level.WARNING, "Could not add conn-bi-direct "
            + "stats string.", e);
      }
    }
    if (this.rawFilesDirectory != null) {
      try {
        if (this.connBiDirectOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.connBiDirectOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/connbidirect.sql"));
          this.connBiDirectOut.write(" COPY connbidirect (source, "
              + "statsend, seconds, belownum, readnum, writenum, "
              + "bothnum) FROM stdin;\n");
        }
        this.connBiDirectOut.write(source + "\t" + statsEnd + "\t"
            + seconds + "\t" + below + "\t" + read + "\t" + write + "\t"
            + both + "\n");
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Could not write conn-bi-direct "
            + "stats string to raw database import file.", e);
      }
    }
  }

  /**
   * Adds observations on the number of directory requests by country as
   * seen on a directory at a given date to the database.
   */
  public void addDirReqStats(String source, String statsEnd, long seconds,
      Map<String, String> dirReqsPerCountry) {
    long statsEndTime = 0L;
    try {
      statsEndTime = this.dateTimeFormat.parse(statsEnd).getTime();
    } catch (ParseException e) {
      this.logger.log(Level.WARNING, "Could not add dirreq stats with "
          + "interval ending '" + statsEnd + "'.", e);
      return;
    }
    if (this.psQs != null && this.psQ != null) {
      try {
        this.addDateToScheduledUpdates(statsEndTime);
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Timestamp statsEndTimestamp = new Timestamp(statsEndTime);
        this.psQs.setString(1, source);
        this.psQs.setTimestamp(2, statsEndTimestamp, cal);
        ResultSet rs = psQs.executeQuery();
        rs.next();
        if (rs.getInt(1) == 0) {
          for (Map.Entry<String, String> e :
              dirReqsPerCountry.entrySet()) {
            this.psQ.clearParameters();
            this.psQ.setString(1, source);
            this.psQ.setTimestamp(2, statsEndTimestamp, cal);
            this.psQ.setLong(3, seconds);
            this.psQ.setString(4, e.getKey());
            this.psQ.setLong(5, Long.parseLong(e.getValue()));
            this.psQ.executeUpdate();
            rqsCount++;
            if (rqsCount % autoCommitCount == 0)  {
              this.conn.commit();
            }
          }
        }
      } catch (SQLException e) {
        this.logger.log(Level.WARNING, "Could not add dirreq stats.", e);
      }
    }
    if (this.rawFilesDirectory != null) {
      try {
        if (this.dirReqOut == null) {
          new File(rawFilesDirectory).mkdirs();
          this.dirReqOut = new BufferedWriter(new FileWriter(
              rawFilesDirectory + "/dirreq_stats.sql"));
          this.dirReqOut.write(" COPY dirreq_stats (source, statsend, "
              + "seconds, country, requests) FROM stdin;\n");
        }
        for (Map.Entry<String, String> e :
            dirReqsPerCountry.entrySet()) {
          this.dirReqOut.write(source + "\t" + statsEnd + "\t" + seconds
              + "\t" + e.getKey() + "\t" + e.getValue() + "\n");
        }
      } catch (IOException e) {
        this.logger.log(Level.WARNING, "Could not write dirreq stats to "
            + "raw database import file.", e);
      }
    }
  }

  /**
   * Close the relay descriptor database connection.
   */
  public void closeConnection() {

    /* Log stats about imported descriptors. */
    this.logger.info(String.format("Finished importing relay "
        + "descriptors: %d consensuses, %d network status entries, %d "
        + "votes, %d server descriptors, %d extra-info descriptors, %d "
        + "bandwidth history elements, %d dirreq stats elements, and %d "
        + "conn-bi-direct stats lines", rcsCount, rrsCount, rvsCount,
        rdsCount, resCount, rhsCount, rqsCount, rbsCount));

    /* Insert scheduled updates a second time, just in case the refresh
     * run has started since inserting them the first time in which case
     * it will miss the data inserted afterwards.  We cannot, however,
     * insert them only now, because if a Java execution fails at a random
     * point, we might have added data, but not the corresponding dates to
     * update statistics. */
    try {
      for (long dateMillis : this.scheduledUpdates) {
        this.psU.setDate(1, new java.sql.Date(dateMillis));
        this.psU.execute();
      }
    } catch (SQLException e) {
      this.logger.log(Level.WARNING, "Could not add scheduled dates for "
          + "the next refresh run.", e);
    }

    /* Commit any stragglers before closing. */
    if (this.conn != null) {
      try {
        this.conn.commit();
      } catch (SQLException e)  {
        this.logger.log(Level.WARNING, "Could not commit final records to "
            + "database", e);
      }
      try {
        this.conn.close();
      } catch (SQLException e) {
        this.logger.log(Level.WARNING, "Could not close database "
            + "connection.", e);
      }
    }

    /* Close raw import files. */
    try {
      if (this.statusentryOut != null) {
        this.statusentryOut.write("\\.\n");
        this.statusentryOut.close();
      }
      if (this.descriptorOut != null) {
        this.descriptorOut.write("\\.\n");
        this.descriptorOut.close();
      }
      if (this.extrainfoOut != null) {
        this.extrainfoOut.write("\\.\n");
        this.extrainfoOut.close();
      }
      if (this.bwhistOut != null) {
        this.bwhistOut.write("\\.\n");
        this.bwhistOut.close();
      }
      if (this.consensusOut != null) {
        this.consensusOut.write("\\.\n");
        this.consensusOut.close();
      }
      if (this.voteOut != null) {
        this.voteOut.write("\\.\n");
        this.voteOut.close();
      }
      if (this.connBiDirectOut != null) {
        this.connBiDirectOut.write("\\.\n");
        this.connBiDirectOut.close();
      }
    } catch (IOException e) {
      this.logger.log(Level.WARNING, "Could not close one or more raw "
          + "database import files.", e);
    }
  }
}

