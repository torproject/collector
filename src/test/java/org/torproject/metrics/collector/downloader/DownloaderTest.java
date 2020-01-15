/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.downloader;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.HashMap;
import java.util.Map;

/**
 * Test class for {@link Downloader}.
 *
 * <p>This test class is heavily based on the blog post
 * <a href="https://claritysoftware.co.uk/mocking-javas-url-with-mockito/">"How
 * to mock the Java URL class with Mockito"</a> by nathan from March 10,
 * 2017.</p>
 */
public class DownloaderTest {

  /**
   * Custom {@link URLStreamHandler} that allows us to control the
   * {@link URLConnection URLConnections} that are returned by {@link URL URLs}
   * in the code under test.
   */
  private static class HttpUrlStreamHandler extends URLStreamHandler {

    private Map<URL, URLConnection> connections = new HashMap<>();

    @Override
    protected URLConnection openConnection(URL url) {
      return this.connections.get(url);
    }

    private void resetConnections() {
      this.connections = new HashMap<>();
    }

    private void addConnection(URL url, URLConnection urlConnection) {
      this.connections.put(url, urlConnection);
    }
  }

  private static HttpUrlStreamHandler httpUrlStreamHandler;

  /**
   * Set up our own stream handler for all tests in this class.
   */
  @BeforeClass
  public static void setupUrlStreamHandlerFactory() {
    URLStreamHandlerFactory urlStreamHandlerFactory
        = mock(URLStreamHandlerFactory.class);
    URL.setURLStreamHandlerFactory(urlStreamHandlerFactory);
    httpUrlStreamHandler = new HttpUrlStreamHandler();
    given(urlStreamHandlerFactory.createURLStreamHandler("http"))
        .willReturn(httpUrlStreamHandler);
  }

  /**
   * Clear any connections from previously run tests.
   */
  @Before
  public void reset() {
    httpUrlStreamHandler.resetConnections();
  }

  @Test
  public void testExistingResource() throws Exception {
    URL requestedUrl = new URL("http://localhost/exists");
    byte[] expectedDownloadedBytes = "content".getBytes();
    HttpURLConnection urlConnection = mock(HttpURLConnection.class);
    httpUrlStreamHandler.addConnection(requestedUrl, urlConnection);
    given(urlConnection.getResponseCode()).willReturn(200);
    given(urlConnection.getInputStream()).willReturn(
        new ByteArrayInputStream(expectedDownloadedBytes));
    byte[] downloadedBytes = Downloader.downloadFromHttpServer(requestedUrl);
    assertArrayEquals(expectedDownloadedBytes, downloadedBytes);
  }

  @Test
  public void testNonExistingResource() throws Exception {
    URL requestedUrl = new URL("http://localhost/notfound");
    HttpURLConnection urlConnection = mock(HttpURLConnection.class);
    httpUrlStreamHandler.addConnection(requestedUrl, urlConnection);
    given(urlConnection.getResponseCode()).willReturn(404);
    byte[] downloadedBytes = Downloader.downloadFromHttpServer(requestedUrl);
    assertNull(downloadedBytes);
  }

  @Test
  public void testEmptyResource() throws Exception {
    URL requestedUrl = new URL("http://localhost/empty");
    byte[] expectedDownloadedBytes = new byte[0];
    HttpURLConnection urlConnection = mock(HttpURLConnection.class);
    httpUrlStreamHandler.addConnection(requestedUrl, urlConnection);
    given(urlConnection.getResponseCode()).willReturn(200);
    given(urlConnection.getInputStream()).willReturn(
        new ByteArrayInputStream(expectedDownloadedBytes));
    byte[] downloadedBytes = Downloader.downloadFromHttpServer(requestedUrl);
    assertEquals(0, downloadedBytes.length);
  }

  @Test(expected = SocketTimeoutException.class)
  public void testTimeout() throws Exception {
    URL requestedUrl = new URL("http://localhost/timeout");
    SocketTimeoutException expectedException = new SocketTimeoutException();
    HttpURLConnection urlConnection = mock(HttpURLConnection.class);
    httpUrlStreamHandler.addConnection(requestedUrl, urlConnection);
    given(urlConnection.getResponseCode()).willReturn(200);
    given(urlConnection.getInputStream()).willThrow(expectedException);
    Downloader.downloadFromHttpServer(requestedUrl);
    fail("Should have thrown a SocketTimeoutException.");
  }
}

