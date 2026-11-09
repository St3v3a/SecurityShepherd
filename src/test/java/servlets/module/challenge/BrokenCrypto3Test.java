package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class BrokenCrypto3Test {
  @Test
  void currentSessionCanDecryptItsExample() {
    HttpSession session = session();
    String token = BrokenCrypto3.exampleCiphertext(session);

    assertEquals("Authenticated encryption protects this example.", decrypt(token, session));
    assertNotEquals(token, BrokenCrypto3.exampleCiphertext(session));
  }

  @Test
  void legacyTamperedAndOtherSessionCiphertextFail() {
    HttpSession session = session();
    String token = BrokenCrypto3.exampleCiphertext(session);
    String tampered =
        token.substring(0, 20) + (token.charAt(20) == 'A' ? 'B' : 'A') + token.substring(21);

    assertThrows(
        GeneralSecurityException.class,
        () -> BrokenCrypto3.decrypt("IAAAAEkQBhEVBwpDHAFJGhYHSBYEGgocAw==", session));
    assertThrows(GeneralSecurityException.class, () -> BrokenCrypto3.decrypt(tampered, session));
    assertThrows(GeneralSecurityException.class, () -> BrokenCrypto3.decrypt(token, session()));
  }

  private static String decrypt(String token, HttpSession session) {
    try {
      return BrokenCrypto3.decrypt(token, session);
    } catch (GeneralSecurityException e) {
      throw new AssertionError(e);
    }
  }

  private static HttpSession session() {
    Map<String, Object> attributes = new HashMap<>();
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(anyString()))
        .thenAnswer(invocation -> attributes.get(invocation.getArgument(0)));
    doAnswer(
            invocation -> {
              attributes.put(invocation.getArgument(0), invocation.getArgument(1));
              return null;
            })
        .when(session)
        .setAttribute(anyString(), any());
    return session;
  }
}
