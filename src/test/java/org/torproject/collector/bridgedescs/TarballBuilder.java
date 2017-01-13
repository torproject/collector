/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import static org.junit.Assert.fail;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds a tarball containing non-sanitized bridge descriptors built using
 * descriptor builders and writes the tarball to a new file with the given file
 * name. */
class TarballBuilder {

  /** Internal helper class to store details about a file contained in the
   * tarball. */
  private class TarballFile {

    /** Last modified time of the file. */
    private long modifiedMillis;

    /** Descriptor builders used to generate the file content. */
    private List<DescriptorBuilder> descriptorBuilders;
  }

  /** File name of the tarball. */
  private String tarballFileName;

  String getTarballFileName() {
    return tarballFileName;
  }

  void setTarballFileName(String tarballFileName) {
    this.tarballFileName = tarballFileName;
  }

  /** Last modified time of the tarball file. */
  private long modifiedMillis;

  /** Files contained in the tarball. */
  private Map<String, TarballFile> tarballFiles;

  /** Initializes a new tarball builder that is going to write a tarball to the
   * file with given file name and last-modified time. */
  TarballBuilder(String tarballFileName, long modifiedMillis) {
    this.tarballFileName = tarballFileName;
    this.modifiedMillis = modifiedMillis;
    this.tarballFiles = new LinkedHashMap<>();
  }

  /** Adds a new file to the tarball with given name, last-modified time, and
   * descriptor builders to generate the file content. */
  TarballBuilder add(String fileName, long modifiedMillis,
      List<DescriptorBuilder> descriptorBuilders) throws IOException {
    TarballFile file = new TarballFile();
    file.modifiedMillis = modifiedMillis;
    file.descriptorBuilders = descriptorBuilders;
    this.tarballFiles.put(fileName, file);
    return this;
  }

  /** Writes the previously configured tarball with all contained files to the
   * given file, or fail if the file extension is not known. */
  void build(File directory) throws IOException {
    File tarballFile = new File(directory, this.tarballFileName);
    TarArchiveOutputStream taos = null;
    if (this.tarballFileName.endsWith(".tar.gz")) {
      taos = new TarArchiveOutputStream(new GzipCompressorOutputStream(
          new BufferedOutputStream(new FileOutputStream(tarballFile))));
    } else if (this.tarballFileName.endsWith(".tar.bz2")) {
      taos = new TarArchiveOutputStream(new BZip2CompressorOutputStream(
          new BufferedOutputStream(new FileOutputStream(tarballFile))));
    } else if (this.tarballFileName.endsWith(".tar")) {
      taos = new TarArchiveOutputStream(new BufferedOutputStream(
          new FileOutputStream(tarballFile)));
    } else {
      fail("Unknown file extension: " + this.tarballFileName);
    }
    for (Map.Entry<String, TarballFile> file : this.tarballFiles.entrySet()) {
      TarArchiveEntry tae = new TarArchiveEntry(file.getKey());
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      for (DescriptorBuilder descriptorBuilder
          : file.getValue().descriptorBuilders) {
        descriptorBuilder.build(baos);
      }
      tae.setSize(baos.size());
      tae.setModTime(file.getValue().modifiedMillis);
      taos.putArchiveEntry(tae);
      taos.write(baos.toByteArray());
      taos.closeArchiveEntry();
    }
    taos.close();
    tarballFile.setLastModified(this.modifiedMillis);
  }
}

