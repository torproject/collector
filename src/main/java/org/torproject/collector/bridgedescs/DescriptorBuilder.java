/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import java.util.ArrayList;
import java.util.List;

/** Builder for descriptors.
 *
 * <p>This builder class can be used while parsing and processing an original
 * descriptor. It accepts {@code String}s, {@code DescriptorBuilder}s and
 * {@code StringBuilder}s. The latter two as placeholders for parts that can
 * only be processed after finishing the parsing step.</p> */
class DescriptorBuilder {

  private List<StringBuilder> parts;

  private StringBuilder lastPart;

  public DescriptorBuilder() {
    this.parts = new ArrayList<>();
    this.lastPart = new StringBuilder();
    this.parts.add(this.lastPart);
  }

  public DescriptorBuilder append(String sanitizedString) {
    this.lastPart.append(sanitizedString);
    return this;
  }

  public DescriptorBuilder append(StringBuilder placeholder) {
    this.parts.add(placeholder);
    this.lastPart = new StringBuilder();
    this.parts.add(this.lastPart);
    return this;
  }

  public DescriptorBuilder space() {
    this.lastPart.append(' ');
    return this;
  }

  public DescriptorBuilder newLine() {
    this.lastPart.append('\n');
    return this;
  }

  @Override
  public String toString() {
    StringBuilder full = new StringBuilder();
    for (StringBuilder part : this.parts) {
      full.append(part);
    }
    return full.toString();
  }
}
