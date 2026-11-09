package utils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import org.owasp.encoder.Encode;

/** Encodes submitted values for the contexts used by the XSS challenge responses. */
public final class SafeHtmlOutput {

  private SafeHtmlOutput() {}

  public static String text(String value) {
    return Encode.forHtml(value == null ? "" : value);
  }

  public static String attribute(String value) {
    return Encode.forHtmlAttribute(value == null ? "" : value);
  }

  public static String httpUrl(String value, String fallback) {
    if (value == null) {
      return fallback;
    }
    try {
      URI uri = new URI(value.trim());
      String scheme = uri.getScheme();
      if ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) {
        URL url = uri.toURL();
        if (url.getHost() != null && !url.getHost().isEmpty()) {
          return url.toExternalForm();
        }
      }
    } catch (URISyntaxException | MalformedURLException e) {
      // Invalid URLs use the challenge's existing safe fallback.
    }
    return fallback;
  }
}
