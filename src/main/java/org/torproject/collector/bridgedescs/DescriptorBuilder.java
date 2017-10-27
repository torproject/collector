/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.bridgedescs;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/** Builder for descriptors.
 *
 * <p>This builder class can be used while parsing and processing an original
 * descriptor. It accepts {@code String}s, {@code DescriptorBuilder}s and
 * {@code StringBuilder}s. The latter two as placeholders for parts that can
 * only be processed after finishing the parsing step.</p>
 *
 * <p>Calling {@code toString} finalizes the builder and any subsequent
 * method calls other than {@code toString} will result in an 
 * {@code IllegalStateException}.
 */
class DescriptorBuilder {

  private List<Object> parts;

  private StringBuilder lastPart;

  private boolean finalized = false;

  private String value;

  public DescriptorBuilder() {
    this.parts = new ArrayList<>();
    this.lastPart = new StringBuilder();
    this.parts.add(this.lastPart);
  }

  private void throwExceptionIfFinalized() {
    if (this.finalized) {
      throw new IllegalStateException("This DescriptorBuilder is finalized and"
          + " calling anything other than 'toString' is illegal.");
    }
  }

  public DescriptorBuilder append(String sanitizedString) {
    this.throwExceptionIfFinalized();
    this.lastPart.append(sanitizedString);
    return this;
  }

  public DescriptorBuilder append(StringBuilder placeholder) {
    this.throwExceptionIfFinalized();
    this.parts.add(placeholder);
    this.lastPart = new StringBuilder();
    this.parts.add(this.lastPart);
    return this;
  }

  public DescriptorBuilder append(DescriptorBuilder placeholder) {
    this.throwExceptionIfFinalized();
    this.parts.add(placeholder);
    this.lastPart = new StringBuilder();
    this.parts.add(this.lastPart);
    return this;
  }

  public DescriptorBuilder space() {
    this.throwExceptionIfFinalized();
    this.lastPart.append(' ');
    return this;
  }

  public DescriptorBuilder newLine() {
    this.throwExceptionIfFinalized();
    this.lastPart.append('\n');
    return this;
  }

  @Override
  public String toString() {
    if (!this.finalized) {
      this.finalized = true;
      this.value = this.parts.stream().map(part -> part.toString())
          .collect(Collectors.joining(""));
      this.parts.clear(); // not needed anymore
      this.lastPart = null;
    }
    return value;
  }

}
