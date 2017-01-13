/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.collector.sync;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.List;

public class FileCollector extends SimpleFileVisitor<Path> {

  final List<File> list;

  FileCollector(List<File> list) {
    this.list = list;
  }

  @Override
  public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
      throws IOException {
    this.list.add(file.toFile());
    return FileVisitResult.CONTINUE;
  }

}
