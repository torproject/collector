/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

import org.torproject.collector.conf.Configuration;
import org.torproject.collector.conf.ConfigurationException;
import org.torproject.collector.conf.Key;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorCollector;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.index.DescriptorIndexCollector;

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

  private static final Logger log = LoggerFactory.getLogger(SyncManager.class);
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

    // The default implementation is less robust.
    DescriptorCollector descriptorCollector = new DescriptorIndexCollector();
    for (URL source : sources) {
      try {
        File storage = new File(basePath.toFile(),
            marker + "-" + source.getHost());
        storage.mkdirs();
        log.info("Collecting {} from {} ...", marker, source.getHost());
        descriptorCollector.collectDescriptors(source.toString(),
            dirs.toArray(new String[dirs.size()]), 0L, storage, true);
        log.info("Done collecting {} from {}.", marker, source.getHost());
      } catch (Throwable th) { // catch all
        log.warn("Cannot download {} from {}.", dirs, source, th);
      }
    }
  }

  private void mergeWithLocalStorage(URL[] sources,
      Map<String, Class<? extends Descriptor>> mapPathDesc,
      String marker, Configuration conf) throws ConfigurationException {
    Path basePath = conf.getPath(Key.SyncPath);
    SyncPersistence persist = new SyncPersistence(conf);
    for (URL source : sources) {
      File base = new File(basePath.toFile(), marker + "-" + source.getHost());
      log.info("Merging {} from {} into storage ...", marker,
          source.getHost());
      for (Map.Entry<String, Class<? extends Descriptor>> entry
          : mapPathDesc.entrySet()) {
        DescriptorReader descriptorReader
            = DescriptorSourceFactory.createDescriptorReader();
        descriptorReader.addDirectory(new File(base, entry.getKey()));
        String histFileEnding = entry.getValue().getSimpleName()
            + (entry.getKey().contains("consensus-microdesc")
               ? "-micro" : "");
        descriptorReader.setExcludeFiles(new File(basePath.toFile(),
            "sync-history-" + source.getHost() + "-" + marker + "-"
            + histFileEnding));
        log.info("Reading {} of type {} ... ", marker, histFileEnding);
        Iterator<DescriptorFile> descriptorFiles
            = descriptorReader.readDescriptors();
        log.info("Done reading {} of type {}.", marker, histFileEnding);
        Criterium crit = new ProcessCriterium(entry.getValue());
        while (descriptorFiles.hasNext()) {
          DescriptorFile descFile = descriptorFiles.next();
          log.debug("Operating on desc-file containing {} descs.",
              descFile.getDescriptors().size());
          if (!crit.applies(descFile)) {
            log.warn("Not processing {} in {}.", descFile.getFileName(),
                descFile.getDirectory());
            continue;
          }

          Exception ex = descFile.getException();
          if (null != ex) {
            log.warn("Parsing of {} caused Exception(s). Processing anyway.",
                descFile.getDirectory() + "/" + descFile.getFileName(), ex);
          }
          persist.storeDescs(descFile.getDescriptors(),
              descFile.getFile().getName(), collectionDate.getTime());
        }
      }
      log.info("Done merging {} from {}.", marker, source.getHost());
    }
  }

}

