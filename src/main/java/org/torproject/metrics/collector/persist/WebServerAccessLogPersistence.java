/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.persist;

import org.torproject.descriptor.WebServerAccessLog;
import org.torproject.metrics.collector.webstats.FileType;
import org.torproject.metrics.collector.webstats.WebServerAccessLogImpl;

import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.format.DateTimeFormatter;

public class WebServerAccessLogPersistence
    extends DescriptorPersistence<WebServerAccessLog> {

  public static final String SEP = WebServerAccessLogImpl.SEP;
  public static final FileType COMPRESSION = FileType.XZ;

  private DateTimeFormatter yearPattern = DateTimeFormatter.ofPattern("yyyy");
  private DateTimeFormatter monthPattern = DateTimeFormatter.ofPattern("MM");
  private DateTimeFormatter dayPattern = DateTimeFormatter.ofPattern("dd");

  /** Prepare storing the given descriptor. */
  public WebServerAccessLogPersistence(WebServerAccessLog desc) {
    super(desc, new byte[0]);
    calculatePaths();
  }

  private void calculatePaths() {
    String name =
        this.desc.getVirtualHost() + SEP + this.desc.getPhysicalHost()
        + SEP + "access.log"
        + SEP + this.desc.getLogDate().format(DateTimeFormatter.BASIC_ISO_DATE)
        + DOT + COMPRESSION.name().toLowerCase();
    this.recentPath = Paths.get(WEBSTATS, name).toString();
    this.storagePath = Paths.get(
        WEBSTATS,
        this.desc.getVirtualHost(),
        this.desc.getLogDate().format(yearPattern), // year
        this.desc.getLogDate().format(monthPattern), // month
        this.desc.getLogDate().format(dayPattern), // day
        name).toString();
  }

  /** Logs are not appended. */
  @Override
  public boolean storeAll(String recentRoot, String outRoot) {
    return storeAll(recentRoot, outRoot, StandardOpenOption.CREATE_NEW,
        StandardOpenOption.CREATE_NEW);
  }

  /** Logs are not appended. */
  @Override
  public boolean storeRecent(String recentRoot) {
    return storeRecent(recentRoot, StandardOpenOption.CREATE_NEW);
  }

}

