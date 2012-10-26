/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.ernie.db.main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.Stack;
import java.util.logging.Logger;

/**
 * Copy files published in the last 3 days to a local directory that can
 * then be served via rsync.
 */
public class RsyncDataProvider {

  private Logger logger;

  private long cutOffMillis;

  private File rsyncDirectory;

  public RsyncDataProvider() {

    /* Initialize logger. */
    this.logger = Logger.getLogger(RsyncDataProvider.class.getName());

    /* Determine the cut-off time for files in rsync/. */
    this.cutOffMillis = System.currentTimeMillis()
        - 3L * 24L * 60L * 60L * 1000L;

    /* Create rsync/ directory if it doesn't exist. */
    this.rsyncDirectory = new File("rsync");
    if (!rsyncDirectory.exists()) {
      rsyncDirectory.mkdirs();
    }
  }

  public void copyFiles(File fromDirectory, String toRsyncSubDirectory) {

    File toDirectory = new File(this.rsyncDirectory, toRsyncSubDirectory);

    /* Make a list of all files in the rsync/ subdirectory to delete those
     * that we didn't copy in this run. */
    Set<String> fileNamesInRsync = new HashSet<String>();
    Stack<File> files = new Stack<File>();
    files.add(toDirectory);
    while (!files.isEmpty()) {
      File pop = files.pop();
      if (pop.isDirectory()) {
        files.addAll(Arrays.asList(pop.listFiles()));
      } else {
        fileNamesInRsync.add(pop.getName());
      }
    }
    logger.info("Found " + fileNamesInRsync.size() + " files in "
        + toDirectory.getAbsolutePath() + " that we're either "
        + "overwriting or deleting in this execution.");

    /* Copy files modified in the last 3 days. */
    files.add(fromDirectory);
    while (!files.isEmpty()) {
      File pop = files.pop();
      if (pop.isDirectory()) {
        files.addAll(Arrays.asList(pop.listFiles()));
      } else if (pop.lastModified() >= this.cutOffMillis) {
        String fileName = pop.getName();
        this.copyFile(pop, new File(toDirectory, fileName));
        fileNamesInRsync.remove(fileName);
      }
    }

    /* Delete all files that we didn't (over-)write in this run. */
    files.add(toDirectory);
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
        + toDirectory.getAbsolutePath() + ".");
  }

  private void copyFile(File from, File to) {
    if (from.exists() && to.exists() &&
        from.lastModified() == to.lastModified() &&
        from.length() == to.length()) {
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
      to.setLastModified(from.lastModified());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
}

