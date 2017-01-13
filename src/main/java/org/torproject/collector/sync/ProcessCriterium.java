/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;

/** Should a descriptor file be processed during sync. */
public class ProcessCriterium implements Criterium<DescriptorFile> {

  private final Class<? extends Descriptor> wantedType;

  public ProcessCriterium(Class<? extends Descriptor> descType) {
    this.wantedType = descType;
  }

  /** Only process descriptors with the appropriate type. */
  @Override
  public boolean applies(DescriptorFile file) {
    for (Descriptor desc : file.getDescriptors()) {
      if (!this.wantedType.isInstance(desc)) {
        return false;
      }
    }
    return true;
  }

}

