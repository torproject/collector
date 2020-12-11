/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.sync;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorCollector;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.UnparseableDescriptor;
import org.torproject.metrics.collector.conf.Configuration;
import org.torproject.metrics.collector.conf.ConfigurationException;
import org.torproject.metrics.collector.conf.Key;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class SyncManager {

  private static final Logger logger
      = LoggerFactory.getLogger(SyncManager.class);
  public static final String SYNCORIGINS = "SyncOrigins";

  private Date collectionDate;

  public SyncManager() { /* empty */ }

  /** Merges the synced files to recent and out storage. */
  public void merge(Configuration conf, String marker,
      Map<String, Class<? extends Descriptor>> mapPathDesc)
      throws ConfigurationException {
    URL[] sources = conf.getUrlArray(Key.valueOf(marker + SYNCORIGINS));
    collectionDate = new Date();
    collectFromOtherInstances(sources, mapPathDesc.keySet(), marker, conf);
    mergeWithLocalStorage(sources, mapPathDesc, marker, conf);
  }

  private void collectFromOtherInstances(URL[] sources, Set<String> dirs,
      String marker, Configuration conf) throws ConfigurationException {
    Path basePath = conf.getPath(Key.SyncPath);

    DescriptorCollector descriptorCollector
        = DescriptorSourceFactory.createDescriptorCollector();
    for (URL source : sources) {
      try {
        File storage = new File(basePath.toFile(),
            marker + "-" + source.getHost());
        storage.mkdirs();
        logger.info("Collecting {} from {} ...", marker, source.getHost());
        descriptorCollector.collectDescriptors(source.toString(),
            dirs.toArray(new String[dirs.size()]), 0L, storage, true);
        logger.info("Done collecting {} from {}.", marker, source.getHost());
      } catch (Throwable th) { // catch all
        logger.warn("Cannot download {} from {}.", dirs, source, th);
      }
    }
  }

  private void mergeWithLocalStorage(URL[] sources,
      Map<String, Class<? extends Descriptor>> mapPathDesc,
      String marker, Configuration conf) throws ConfigurationException {
    Path basePath = conf.getPath(Key.SyncPath);
    SyncPersistence persist = new SyncPersistence(conf);
    Criterium<Descriptor> unparseable
        = new ProcessCriterium(UnparseableDescriptor.class);
    for (URL source : sources) {
      File base = new File(basePath.toFile(), marker + "-" + source.getHost());
      logger.info("Merging {} from {} into storage ...", marker,
          source.getHost());
      for (Map.Entry<String, Class<? extends Descriptor>> entry
          : mapPathDesc.entrySet()) {
        File descFile = new File(base, entry.getKey());
        DescriptorReader descriptorReader
            = DescriptorSourceFactory.createDescriptorReader();
        String histFileEnding = entry.getValue().getSimpleName()
            + (entry.getKey().contains("consensus-microdesc")
               ? "-micro" : "");
        File historyFile = new File(basePath.toFile(),
            "sync-history-" + source.getHost() + "-" + marker + "-"
            + histFileEnding);
        descriptorReader.setHistoryFile(historyFile);
        logger.info("Reading {} of type {} ... ", marker, histFileEnding);
        Iterator<Descriptor> descriptors
            = descriptorReader.readDescriptors(descFile).iterator();
        logger.info("Done reading {} of type {}.", marker, histFileEnding);
        Criterium<Descriptor> crit = new ProcessCriterium(entry.getValue());
        while (descriptors.hasNext()) {
          Descriptor desc = descriptors.next();
          if (unparseable.applies(desc)) {
            Exception ex
                = ((UnparseableDescriptor)desc).getDescriptorParseException();
            logger.warn("Parsing of {} caused Exception(s). Processing anyway.",
                desc.getDescriptorFile(), ex);
          }
          if (!crit.applies(desc)) {
            logger.warn("Not processing {} in {}.", desc.getClass().getName(),
                desc.getDescriptorFile());
            continue;
          }

          persist.storeDesc(desc, collectionDate.getTime());
        }
        descriptorReader.saveHistoryFile(historyFile);
      }
      logger.info("Done merging {} from {}.", marker, source.getHost());
    }
    persist.cleanDirectory();
  }

}

