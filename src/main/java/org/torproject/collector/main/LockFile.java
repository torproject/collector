/* Copyright 2010--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Logger;

public class LockFile {

  private final File lockFile;
  private final String moduleName;
  private final Logger logger = Logger.getLogger(LockFile.class.getName());

  public LockFile(String moduleName) {
    this("lock", moduleName);
  }

  public LockFile(String lockFilePath, String moduleName) {
    this.lockFile = new File(lockFilePath, moduleName);
    this.moduleName = moduleName;
  }

  public boolean acquireLock() {
    this.logger.fine("Trying to acquire lock...");
    try {
      if (this.lockFile.exists()) {
        BufferedReader br = new BufferedReader(new FileReader(
            this.lockFile));
        long runStarted = Long.parseLong(br.readLine());
        br.close();
        if (System.currentTimeMillis() - runStarted < 55L * 60L * 1000L) {
          throw new RuntimeException("Cannot acquire lock for " + moduleName);
        }
      }
      this.lockFile.getParentFile().mkdirs();
      BufferedWriter bw = new BufferedWriter(new FileWriter(
          this.lockFile));
      bw.append("" + System.currentTimeMillis() + "\n");
      bw.close();
      this.logger.fine("Acquired lock.");
      return true;
    } catch (IOException e) {
      throw new RuntimeException("Caught exception while trying to acquire "
          + "lock for " + moduleName);
    }
  }

  public void releaseLock() {
    this.logger.fine("Releasing lock...");
    this.lockFile.delete();
    this.logger.fine("Released lock.");
  }
}

