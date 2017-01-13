/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Builds a descriptor by concatenating the given lines with newlines and
 * writing the output to the given output stream. */
abstract class DescriptorBuilder extends ArrayList<String> {

  /** Removes the given line, or fails if that line cannot be found. */
  void removeLine(String line) {
    if (!this.remove(line)) {
      fail("Line not contained: " + line);
    }
  }

  /** Removes all but the given line, or fails if that line cannot be found. */
  void removeAllExcept(String line) {
    assertTrue("Line not contained: " + line, this.contains(line));
    this.retainAll(Arrays.asList(line));
  }

  /** Finds the first line that starts with the given line start and inserts the
   * given lines before it, or fails if no line can be found with that line
   * start. */
  void insertBeforeLineStartingWith(String lineStart,
      List<String> linesToInsert) {
    for (int i = 0; i < this.size(); i++) {
      if (this.get(i).startsWith(lineStart)) {
        this.addAll(i, linesToInsert);
        return;
      }
    }
    fail("Line start not found: " + lineStart);
  }

  /** Finds the first line that starts with the given line start and replaces
   * that line and possibly subsequent lines, or fails if no line can be found
   * with that line start or there are not enough lines left to replace. */
  void replaceLineStartingWith(String lineStart, List<String> linesToReplace) {
    for (int i = 0; i < this.size(); i++) {
      if (this.get(i).startsWith(lineStart)) {
        for (int j = 0; j < linesToReplace.size(); j++) {
          assertTrue("Not enough lines left to replace.",
              this.size() > i + j);
          this.set(i + j, linesToReplace.get(j));
        }
        return;
      }
    }
    fail("Line start not found: " + lineStart);
  }

  /** Writes all descriptor lines with newlines to the given output stream. */
  void build(OutputStream outputStream) throws IOException {
    for (String line : this) {
      outputStream.write((line + "\n").getBytes());
    }
  }
}

