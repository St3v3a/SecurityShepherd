package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagement5ResetTokenTest {
  @Test
  void tokenIsBoundToUserAndSessionAndCanOnlyBeUsedOnce() {
    HttpSession session = session();
    String token = SessionManagement5ResetToken.issue(session, "manager");

    assertFalse(SessionManagement5ResetToken.consume(session, "sean", token));
    assertFalse(SessionManagement5ResetToken.consume(session(), "manager", token));
    assertFalse(SessionManagement5ResetToken.consume(session, "manager", "forged"));
    assertTrue(SessionManagement5ResetToken.consume(session, "manager", token));
    assertFalse(SessionManagement5ResetToken.consume(session, "manager", token));
  }

  @Test
  void expiredTokenIsRejected() {
    HttpSession session = session();
    String token = SessionManagement5ResetToken.issue(session, "manager");
    session.setAttribute(
        SessionManagement5ResetToken.class.getName() + ".expires", System.currentTimeMillis() - 1);

    assertFalse(SessionManagement5ResetToken.consume(session, "manager", token));
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
    doAnswer(
            invocation -> {
              attributes.remove(invocation.getArgument(0));
              return null;
            })
        .when(session)
        .removeAttribute(anyString());
    return session;
  }
}
