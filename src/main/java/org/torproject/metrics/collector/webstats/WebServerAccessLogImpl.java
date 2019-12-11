/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.WebServerAccessLog;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Implementation of web server access log descriptors.
 *
 * <p>Defines sanitization and validation for web server access logs.</p>
 *
 * @since 2.2.0
 */
public class WebServerAccessLogImpl implements WebServerAccessLog {

  /** Logfile name parts separator. */
  public static final String SEP = "_";

  /** The log's name should include this string. */
  public static final String MARKER = "access.log";

  /** The mandatory web server log descriptor file name pattern. */
  public static final Pattern filenamePattern
      = Pattern.compile("(\\S*)" + SEP + "(\\S*)" + SEP + "" + MARKER
      + SEP + "(\\d*)(?:\\.?)([a-zA-Z]*)");

  private final File descriptorFile;

  /** Byte array for plain, i.e. uncompressed, log data. */
  private byte[] logBytes;

  private FileType fileType;

  private List<String> unrecognizedLines = new ArrayList<>();

  private final String physicalHost;

  private final String virtualHost;

  private final LocalDate logDate;

  /**
   * Creates a WebServerAccessLog from the given bytes and filename.
   *
   * <p>The given bytes are read, whereas the file is not read.</p>
   *
   * <p>The path of the given file has to be compliant to the following
   * naming pattern
   * {@code
   * <virtualHost>-<physicalHost>-access.log-<yyyymmdd>.<compression>},
   * where an unknown compression type (see {@link #getCompressionType})
   * is interpreted as missing compression.  In this case the bytes
   * will be compressed to the default compression type.
   * The immediate parent name is taken to be the physical host collecting the
   * logs.</p>
   */
  protected WebServerAccessLogImpl(byte[] logBytes, File descriptorFile,
      String logName) throws DescriptorParseException {
    this.logBytes = logBytes;
    this.descriptorFile = descriptorFile;
    try {
      Matcher mat = filenamePattern.matcher(logName);
      if (!mat.find()) {
        throw new DescriptorParseException(
            "Log file name doesn't comply to standard: " + logName);
      }
      this.virtualHost = mat.group(1);
      this.physicalHost = mat.group(2);
      if (null == this.virtualHost || null == this.physicalHost
          || this.virtualHost.isEmpty() || this.physicalHost.isEmpty()) {
        throw new DescriptorParseException(
            "WebServerAccessLog file name doesn't comply to standard: "
            + logName);
      }
      String ymd = mat.group(3);
      this.logDate = LocalDate.parse(ymd, DateTimeFormatter.BASIC_ISO_DATE);
      this.fileType = FileType.findType(mat.group(4).toUpperCase());
      if (FileType.PLAIN == this.fileType) {
        this.fileType = FileType.XZ;
        this.logBytes = this.fileType.compress(this.logBytes);
      }
    } catch (DescriptorParseException dpe) {
      throw dpe; // escalate
    } catch (Exception pe) {
      throw new DescriptorParseException(
          "Cannot parse WebServerAccessLog file: " + logName, pe);
    }
  }

  /**
   * Creates an empty WebServerAccessLog from the given filename parts.
   *
   * <p>This instance is not intended to be written to disk, as it doesn't have
   * any content. The main intention of this instance is to compute storage
   * paths.</p>
   *
   * @param virtualHost Virtual host name.
   * @param physicalHost Physical host name.
   * @param logDate Log date.
   */
  protected WebServerAccessLogImpl(String virtualHost, String physicalHost,
      LocalDate logDate) {
    this.descriptorFile = null;
    this.virtualHost = virtualHost;
    this.physicalHost = physicalHost;
    this.logDate = logDate;
  }

  @Override
  public InputStream decompressedByteStream() throws DescriptorParseException {
    try {
      return this.fileType.decompress(new ByteArrayInputStream(this.logBytes));
    } catch (Exception ex) {
      throw new DescriptorParseException("Cannot provide deflated stream of "
          + this.descriptorFile + ".", ex);
    }
  }

  public String getCompressionType() {
    return this.fileType.name().toLowerCase();
  }

  @Override
  public byte[] getRawDescriptorBytes() {
    return this.logBytes;
  }

  public void setRawDescriptorBytes(byte[] bytes) {
    this.logBytes = bytes;
  }

  @Override
  public int getRawDescriptorLength() {
    return this.logBytes.length;
  }

  @Override
  public List<String> getAnnotations() {
    return Collections.emptyList();
  }

  @Override
  public List<String> getUnrecognizedLines() {
    return this.unrecognizedLines;
  }

  @Override
  public File getDescriptorFile() {
    return descriptorFile;
  }

  @Override
  public String getPhysicalHost() {
    return this.physicalHost;
  }

  @Override
  public String getVirtualHost() {
    return this.virtualHost;
  }

  @Override
  public LocalDate getLogDate() {
    return this.logDate;
  }

  private static final int LISTLIMIT = Integer.MAX_VALUE / 2;

  /** Returns a stream of all valid log lines. */
  @Override
  public Stream<WebServerAccessLog.Line> logLines()
      throws DescriptorParseException {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(
        this.decompressedByteStream()))) {
      List<List<WebServerAccessLogLine>> lists = new ArrayList<>();
      List<WebServerAccessLogLine> currentList = new ArrayList<>();
      lists.add(currentList);
      String lineStr = br.readLine();
      int count = 0;
      while (null != lineStr) {
        WebServerAccessLogLine wsal = WebServerAccessLogLine.makeLine(lineStr);
        if (wsal.isValid()) {
          currentList.add(wsal);
          count++;
        }
        if (count >= LISTLIMIT) {
          currentList = new ArrayList<>();
          lists.add(currentList);
          count = 0;
        }
        lineStr = br.readLine();
      }
      br.close();
      return lists.stream().flatMap(Collection::stream);
    } catch (Exception ex) {
      throw new DescriptorParseException("Cannot retrieve log lines.", ex);
    }
  }

}

