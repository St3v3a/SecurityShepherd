package servlets.module.challenge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/** A one-use reset token tied to an administrator session and a subaccount. */
final class SessionManagement5ResetToken {
  private static final String PREFIX = SessionManagement5ResetToken.class.getName();
  private static final String DIGEST = PREFIX + ".digest";
  private static final String USER = PREFIX + ".user";
  private static final String EXPIRES = PREFIX + ".expires";
  private static final long VALID_FOR_MILLIS = 5 * 60 * 1000L;
  private static final SecureRandom RANDOM = new SecureRandom();

  private SessionManagement5ResetToken() {}

  static String issue(HttpSession session, String userName) {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    synchronized (session) {
      session.setAttribute(DIGEST, digest(token));
      session.setAttribute(USER, userName);
      session.setAttribute(EXPIRES, System.currentTimeMillis() + VALID_FOR_MILLIS);
    }
    return token;
  }

  static boolean consume(HttpSession session, String userName, String token) {
    if (session == null || userName == null || token == null || token.length() > 128) {
      return false;
    }
    synchronized (session) {
      Object expected = session.getAttribute(DIGEST);
      Object boundUser = session.getAttribute(USER);
      Object expires = session.getAttribute(EXPIRES);
      if (!(expected instanceof byte[])
          || !(expires instanceof Long)
          || (Long) expires < System.currentTimeMillis()
          || !userName.equals(boundUser)
          || !MessageDigest.isEqual((byte[]) expected, digest(token))) {
        return false;
      }
      session.removeAttribute(DIGEST);
      session.removeAttribute(USER);
      session.removeAttribute(EXPIRES);
      return true;
    }
  }

  private static byte[] digest(String token) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.US_ASCII));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }
}
