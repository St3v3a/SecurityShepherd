package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SafeHtmlOutputTest {

  private static final String FALLBACK = "https://www.owasp.org/index.php/OWASP_Security_Shepherd";

  @Test
  void renderedSearchTermsCannotBecomeMarkup() {
    String one = SafeHtmlOutput.text(XssFilter.levelOne("<img src=x onerror=alert(1)>"));
    String two = SafeHtmlOutput.text(XssFilter.levelTwo("<img src=x onmouseenter=alert(1)>"));
    String three =
        SafeHtmlOutput.text(XssFilter.levelThree("<img src=x onononloadloadload=alert(1)>"));
    for (String rendered : new String[] {one, two, three}) {
      assertFalse(rendered.contains("<img"));
      assertFalse(FindXSS.search(rendered));
    }
    assertEquals("Normal Search", SafeHtmlOutput.text("Normal Search"));
  }

  @Test
  void renderedLinksKeepQuotesInsideAttributes() {
    for (String raw :
        new String[] {
          "http\" href=javascript:alert(1) x=\"",
          "http://x\"\" onmouseover=alert(1)",
          "javascript:alert(1)"
        }) {
      String safeUrl = SafeHtmlOutput.httpUrl(raw, FALLBACK);
      String anchor =
          "<a href=\""
              + SafeHtmlOutput.attribute(safeUrl)
              + "\">"
              + SafeHtmlOutput.text(safeUrl)
              + "</a>";
      assertFalse(FindXSS.search(anchor));
    }
    String normal = "https://example.org/path?q=a&b=c#fragment";
    assertEquals(normal, SafeHtmlOutput.httpUrl(normal, FALLBACK));
    assertTrue(SafeHtmlOutput.attribute(normal).contains("&amp;"));
    assertEquals(
        "https://münich.example/path",
        SafeHtmlOutput.httpUrl("https://münich.example/path", FALLBACK));
    assertEquals(
        "http://intranet_host/path", SafeHtmlOutput.httpUrl("http://intranet_host/path", FALLBACK));
    assertEquals(
        "https://user:pass@example.org/path",
        SafeHtmlOutput.httpUrl("https://user:pass@example.org/path", FALLBACK));
  }
}
