package org.torproject.collector.bridgedescs;

import java.util.ArrayList;
import java.util.List;

/** Builder for sanitized bridge descriptors.
 *
 * <p>This builder class can be used while parsing and sanitizing an original
 * bridge descriptor. It accepts already sanitized {@code String}s and
 * {@code StringBuilder}s as placeholders for parts that can only be sanitized
 * after finishing the parsing step.</p> */
class SanitizedBridgeDescriptorBuilder {

  private List<StringBuilder> descriptorParts;

  private StringBuilder lastDescriptorPart;

  SanitizedBridgeDescriptorBuilder() {
    this.descriptorParts = new ArrayList<>();
    this.lastDescriptorPart = new StringBuilder();
    this.descriptorParts.add(this.lastDescriptorPart);
  }

  SanitizedBridgeDescriptorBuilder append(String sanitizedString) {
    this.lastDescriptorPart.append(sanitizedString);
    return this;
  }

  SanitizedBridgeDescriptorBuilder append(StringBuilder placeholder) {
    this.descriptorParts.add(placeholder);
    this.lastDescriptorPart = new StringBuilder();
    this.descriptorParts.add(this.lastDescriptorPart);
    return this;
  }

  SanitizedBridgeDescriptorBuilder space() {
    this.lastDescriptorPart.append(' ');
    return this;
  }

  SanitizedBridgeDescriptorBuilder newLine() {
    this.lastDescriptorPart.append('\n');
    return this;
  }

  @Override
  public String toString() {
    StringBuilder fullDescriptor = new StringBuilder();
    for (StringBuilder descriptorPart : this.descriptorParts) {
      fullDescriptor.append(descriptorPart);
    }
    return fullDescriptor.toString();
  }
}
