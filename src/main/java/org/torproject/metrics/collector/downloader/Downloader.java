/* Copyright 2019--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.metrics.collector.downloader;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.InflaterInputStream;

/**
 * Utility class for downloading resources from HTTP servers.
 */
public class Downloader {

  /**
   * Download the given URL from an HTTP server and return downloaded bytes.
   *
   * @param url URL to download.
   * @return Downloaded bytes, or {@code null} if the resource was not found.
   * @throws IOException Thrown if anything goes wrong while downloading.
   */
  public static byte[] downloadFromHttpServer(URL url) throws IOException {
    return Downloader.downloadFromHttpServer(url, false);
  }

  /**
   * Download the given URL from an HTTP server, possibly inflate the response,
   * and return downloaded bytes.
   *
   * @param url URL to download.
   * @param isDeflated Whether the response is deflated.
   * @return Downloaded bytes, or {@code null} if the resource was not found.
   * @throws IOException Thrown if anything goes wrong while downloading.
   */
  public static byte[] downloadFromHttpServer(URL url, boolean isDeflated)
      throws IOException {
    ByteArrayOutputStream downloadedBytes = new ByteArrayOutputStream();
    HttpURLConnection huc = (HttpURLConnection) url.openConnection();
    huc.setRequestMethod("GET");
    huc.setReadTimeout(5000);
    huc.connect();
    int response = huc.getResponseCode();
    if (response != 200) {
      return null;
    }
    try (BufferedInputStream in = isDeflated
        ? new BufferedInputStream(new InflaterInputStream(
            huc.getInputStream()))
        : new BufferedInputStream(huc.getInputStream())) {
      int len;
      byte[] data = new byte[1024];
      while ((len = in.read(data, 0, 1024)) >= 0) {
        downloadedBytes.write(data, 0, len);
      }
    }
    return downloadedBytes.toByteArray();
  }
}

