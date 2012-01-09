/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db;

import java.io.*;
import java.util.*;

/**
 * Copy files published in the last 3 days to a local directory that can
 * then be served via rsync.
 */
public class RsyncDataProvider {
  public RsyncDataProvider(File directoryArchivesOutputDirectory,
      File sanitizedBridgesWriteDirectory,
      File sanitizedAssignmentsDirectory, File rsyncDirectory) {

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

    /* Delete all files that we didn't (over-)write in this run. */
    files.add(rsyncDirectory);
    while (!files.isEmpty()) {
      File pop = files.pop();
      if (pop.isDirectory()) {
        files.addAll(Arrays.asList(pop.listFiles()));
      } else if (fileNamesInRsync.contains(pop.getName())) {
        pop.delete();
      }
    }
  }

  private void copyFile(File from, File to) {
    if (to.exists()) {
      return;
    }
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
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}

