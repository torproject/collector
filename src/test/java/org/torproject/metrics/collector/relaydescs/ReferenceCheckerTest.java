/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.relaydescs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;

public class ReferenceCheckerTest {

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private static final String validReferenceJson
      = "[{\"referencing\":\"C-2016-09-17T03:00:00Z\","
      + "\"referenced\":\"S-D8736FB5916322CB4B0FC34FA9DA3D8ACBBCE352\","
      + "\"weight\":0.028224668360146768,"
      + "\"expiresAfterMillis\":33455631600000}]";

  @Test()
  public void testValidJson() throws Exception {
    File descDir = tmpf.newFolder();
    File refsFile = tmpf.newFile();
    File histFile = tmpf.newFile();
    Files.write(refsFile.toPath(), validReferenceJson.getBytes());
    assertEquals(validReferenceJson, Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
    ReferenceChecker rc = new ReferenceChecker(descDir, refsFile, histFile);
    rc.check();
    assertTrue(refsFile.exists());
    assertEquals(validReferenceJson, Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
  }

  @Test()
  public void testInvalidJson() throws Exception {
    File descDir = tmpf.newFolder();
    File refsFile = tmpf.newFile();
    File histFile = tmpf.newFile();
    String badJson = "[{\"xx\":7]}";
    Files.write(refsFile.toPath(), badJson.getBytes());
    assertEquals(badJson, Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
    ReferenceChecker rc = new ReferenceChecker(descDir, refsFile, histFile);
    rc.check();
    assertTrue(refsFile.exists());
    assertEquals("[]", Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
  }

  @Test()
  public void testMinimalValidJson() throws Exception {
    File descDir = tmpf.newFolder();
    File refsFile = tmpf.newFile();
    File histFile = tmpf.newFile();
    Files.write(refsFile.toPath(), "[]".getBytes());
    ReferenceChecker rc = new ReferenceChecker(descDir, refsFile, histFile);
    rc.check();
    assertTrue(refsFile.exists());
    assertEquals("The file's contents shouldn't have changed, but did.", "[]",
        Files.readAllLines(refsFile.toPath(), Charset.forName("US-ASCII"))
            .get(0));
  }

  @Test()
  public void testEmptyReferencedString() throws Exception {
    String validEmptyReferencedString
        = validReferenceJson.substring(0,
        validReferenceJson.indexOf("S-D8736"))
        + validReferenceJson.substring(
        validReferenceJson.indexOf("\",\"weight"));
    File descDir = tmpf.newFolder();
    File refsFile = tmpf.newFile();
    File histFile = tmpf.newFile();
    Files.write(refsFile.toPath(), validEmptyReferencedString.getBytes());
    assertEquals(validEmptyReferencedString,
        Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
    ReferenceChecker rc = new ReferenceChecker(descDir, refsFile, histFile);
    rc.check();
    assertTrue(refsFile.exists());
    assertEquals(validEmptyReferencedString,
        Files.readAllLines(refsFile.toPath(),
        Charset.forName("US-ASCII")).get(0));
  }
}

