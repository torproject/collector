/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.util.*;
import java.util.logging.*;

/**
 * Copy files published in the last 3 days to a local directory that can
 * then be served via rsync.
 */
public class RsyncDataProvider {
  public RsyncDataProvider(File directoryArchivesOutputDirectory,
      File sanitizedBridgesWriteDirectory,
      File sanitizedAssignmentsDirectory, File rsyncDirectory) {

    /* Initialize logger. */
    Logger logger = Logger.getLogger(RsyncDataProvider.class.getName());

    /* Determine the cut-off time for files in rsync/. */
    long cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;

    /* Create rsync/ directory if it doesn't exist. */
    if (!rsyncDirectory.exists()) {
      rsyncDirectory.mkdirs();
    }

    /* Make a list of all files in the rsync/ directory to delete those
     * that we didn't copy in this run. */
    Set<String> fileNamesInRsync = new HashSet<String>();
    Stack<File> files = new Stack<File>();
    files.add(rsyncDirectory);
    while (!files.isEmpty()) {
      File pop = files.pop();
      if (pop.isDirectory()) {
        files.addAll(Arrays.asList(pop.listFiles()));
      } else {
        fileNamesInRsync.add(pop.getName());
      }
    }
    logger.info("Found " + fileNamesInRsync.size() + " files in "
        + rsyncDirectory.getAbsolutePath() + " that we're either "
        + "overwriting or deleting in this execution.");

    /* Copy relay descriptors from the last 3 days. */
    if (directoryArchivesOutputDirectory != null) {
      files.add(directoryArchivesOutputDirectory);
      while (!files.isEmpty()) {
        File pop = files.pop();
        if (pop.isDirectory()) {
          files.addAll(Arrays.asList(pop.listFiles()));
        } else if (pop.lastModified() >= cutOffMillis) {
          String fileName = pop.getName();
          if (pop.getAbsolutePath().contains("/consensus/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "relay-descriptors/consensuses/" + fileName));
          } else if (pop.getAbsolutePath().contains("/vote/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "relay-descriptors/votes/" + fileName));
          } else if (pop.getAbsolutePath().contains(
                "/server-descriptor/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "relay-descriptors/server-descriptors/" + fileName));
          } else if (pop.getAbsolutePath().contains("/extra-info/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "relay-descriptors/extra-infos/" + fileName));
          } else {
            continue;
          }
          fileNamesInRsync.remove(pop.getName());
        }
      }
    }
    logger.info("After copying relay descriptors, there are still "
        + fileNamesInRsync.size() + " files left in "
        + rsyncDirectory.getAbsolutePath() + ".");

    /* Copy sanitized bridge descriptors from the last 3 days. */
    if (sanitizedBridgesWriteDirectory != null) {
      files.add(sanitizedBridgesWriteDirectory);
      while (!files.isEmpty()) {
        File pop = files.pop();
        if (pop.isDirectory()) {
          files.addAll(Arrays.asList(pop.listFiles()));
        } else if (pop.lastModified() >= cutOffMillis) {
          String fileName = pop.getName();
          if (pop.getAbsolutePath().contains("/statuses/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "bridge-descriptors/statuses/" + fileName));
          } else if (pop.getAbsolutePath().contains(
                "/server-descriptors/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "bridge-descriptors/server-descriptors/" + fileName));
          } else if (pop.getAbsolutePath().contains("/extra-infos/")) {
            this.copyFile(pop, new File(rsyncDirectory,
                "bridge-descriptors/extra-infos/" + fileName));
          } else {
            continue;
          }
          fileNamesInRsync.remove(pop.getName());
        }
      }
    }
    logger.info("After copying sanitized bridge descriptors, there are "
        + "still " + fileNamesInRsync.size() + " files left in "
        + rsyncDirectory.getAbsolutePath() + ".");

    /* Copy sanitized bridge pool assignments from the last 3 days. */
    if (sanitizedAssignmentsDirectory != null) {
      files.add(sanitizedAssignmentsDirectory);
      while (!files.isEmpty()) {
        File pop = files.pop();
        if (pop.isDirectory()) {
          files.addAll(Arrays.asList(pop.listFiles()));
        } else if (pop.lastModified() >= cutOffMillis) {
          String fileName = pop.getName();
          this.copyFile(pop, new File(rsyncDirectory,
              "bridge-pool-assignments/" + fileName));
          fileNamesInRsync.remove(pop.getName());
        }
      }
    }
    logger.info("After copying sanitized bridge pool assignments, there "
        + "are still " + fileNamesInRsync.size() + " files left in "
        + rsyncDirectory.getAbsolutePath() + ".");

    /* Delete all files that we didn't (over-)write in this run. */
    files.add(rsyncDirectory);
    while (!files.isEmpty()) {
      File pop = files.pop();
      if (pop.isDirectory()) {
        files.addAll(Arrays.asList(pop.listFiles()));
      } else if (fileNamesInRsync.contains(pop.getName())) {
        fileNamesInRsync.remove(pop.getName());
        pop.delete();
      }
    }
    logger.info("After deleting files that we didn't overwrite in this "
        + "run, there are " + fileNamesInRsync.size() + " files left in "
        + rsyncDirectory.getAbsolutePath() + ".");
  }

  private void copyFile(File from, File to) {
    try {
      to.getParentFile().mkdirs();
      FileInputStream fis = new FileInputStream(from);
      BufferedInputStream bis = new BufferedInputStream(fis);
      FileOutputStream fos = new FileOutputStream(to);
      int len;
      byte[] data = new byte[1024];
      while ((len = bis.read(data, 0, 1024)) >= 0) {
        fos.write(data, 0, len);
      }
      bis.close();
      fos.close();
      to.setLastModified(from.lastModified());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}

