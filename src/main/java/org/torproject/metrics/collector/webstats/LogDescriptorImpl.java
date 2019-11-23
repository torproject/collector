/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.webstats;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.LogDescriptor;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Base class for log descriptors.
 *
 * @since 2.2.0
 */
public abstract class LogDescriptorImpl
    implements LogDescriptor, InternalLogDescriptor {

  /** The log's file name should contain this string. */
  public static final String MARKER = ".log";

  private static Pattern filenamePattern = Pattern.compile(
      "(?:\\S*)" + MARKER + SEP + "(?:[0-9a-zA-Z]*)(?:\\.?)([a-zA-Z2]*)");

  private final File descriptorFile;

  /** Byte array for plain, i.e. uncompressed, log data. */
  private byte[] logBytes;

  private FileType fileType;

  private List<String> unrecognizedLines = new ArrayList<>();

  /**
   * This constructor performs basic operations on the given bytes.
   *
   * <p>An unknown compression type (see {@link #getCompressionType})
   * is interpreted as missing compression.  In this case the bytes
   * will be compressed to the given compression type.</p>
   *
   * @since 2.2.0
   */
  protected LogDescriptorImpl(byte[] logBytes, File descriptorFile,
      String logName) throws DescriptorParseException {
    this.logBytes = logBytes;
    this.descriptorFile = descriptorFile;
    try {
      Matcher mat = filenamePattern.matcher(logName);
      if (!mat.find()) {
        throw new DescriptorParseException(
            "Log file name doesn't comply to standard: " + logName);
      }
      this.fileType = FileType.findType(mat.group(1).toUpperCase());
      if (FileType.PLAIN == this.fileType) {
        this.fileType = FileType.XZ;
        this.logBytes = this.fileType.compress(this.logBytes);
      }
    } catch (Exception ex) {
      throw new DescriptorParseException("Cannot parse file "
          + logName + " from file " + descriptorFile.getName(), ex);
    }
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

  @Override
  public String getCompressionType() {
    return this.fileType.name().toLowerCase();
  }

  @Override
  public byte[] getRawDescriptorBytes() {
    return this.logBytes;
  }

  @Override
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

}

