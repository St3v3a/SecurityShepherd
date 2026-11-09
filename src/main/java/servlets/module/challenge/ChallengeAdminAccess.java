package servlets.module.challenge;

import dbProcs.Getter;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import utils.Validate;

/** Requires a fresh password confirmation before using privileged challenge functions. */
public class ChallengeAdminAccess extends HttpServlet {
  private static final long serialVersionUID = 1L;
  private static final String VERIFIED_AT = ChallengeAdminAccess.class.getName() + ".verifiedAt";
  private static final String FAILED_ATTEMPTS =
      ChallengeAdminAccess.class.getName() + ".failedAttempts";
  private static final String LOCKED_UNTIL = ChallengeAdminAccess.class.getName() + ".lockedUntil";
  private static final long VALID_FOR_MILLIS = 5 * 60 * 1000L;
  private static final long LOCK_MILLIS = 15 * 60 * 1000L;

  static boolean isVerified(HttpSession session) {
    if (session == null || !"admin".equals(session.getAttribute("userRole"))) {
      return false;
    }
    Object value = session.getAttribute(VERIFIED_AT);
    if (!(value instanceof Long)) {
      return false;
    }
    long age = System.currentTimeMillis() - (Long) value;
    return age >= 0 && age <= VALID_FOR_MILLIS;
  }

  /** Records a fresh, successful SSO authentication for a platform administrator. */
  public static void markSsoVerified(HttpSession session) {
    if (session != null && "admin".equals(session.getAttribute("userRole"))) {
      session.setAttribute(VERIFIED_AT, System.currentTimeMillis());
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    HttpSession session = request.getSession(false);
    if (!Validate.validateSession(session)
        || !"admin".equals(session.getAttribute("userRole"))
        || !Validate.validateTokens(
            Validate.getToken(request.getCookies()), request.getParameter("csrfToken"))) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    String password = request.getParameter("currentPassword");
    if (password == null || password.isEmpty()) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    synchronized (session) {
      Object lockedUntil = session.getAttribute(LOCKED_UNTIL);
      if (lockedUntil instanceof Long && (Long) lockedUntil > System.currentTimeMillis()) {
        response.sendError(429);
        return;
      }
      String[] user =
          Getter.authUser(
              getServletContext().getRealPath(""),
              (String) session.getAttribute("userName"),
              password);
      if (user == null
          || user[0].isEmpty()
          || !user[0].equals(session.getAttribute("userStamp"))
          || !"admin".equals(user[2])) {
        Object priorFailures = session.getAttribute(FAILED_ATTEMPTS);
        int failures = priorFailures instanceof Integer ? (Integer) priorFailures + 1 : 1;
        session.setAttribute(FAILED_ATTEMPTS, failures);
        if (failures >= 5) {
          session.setAttribute(LOCKED_UNTIL, System.currentTimeMillis() + LOCK_MILLIS);
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
        return;
      }
      session.removeAttribute(FAILED_ATTEMPTS);
      session.removeAttribute(LOCKED_UNTIL);
      session.setAttribute(VERIFIED_AT, System.currentTimeMillis());
    }
    response.setContentType("text/html;charset=UTF-8");
    response.getWriter().write("<p>Administrator access confirmed for this session.</p>");
  }
}
