package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Administrator-assisted Session Management Two password reset <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class SessionManagement2ChangePassword extends HttpServlet {
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static final SecureRandom RANDOM = new SecureRandom();

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession session = request.getSession(false);
    if (!Validate.validateSession(session)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    Locale locale = new Locale(Validate.validateLanguage(session));
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    response.setContentType("text/html;charset=UTF-8");
    response.setHeader("Cache-Control", "no-store");
    String requestReceived = "<p>" + bundle.getString("response.resetRequestReceived") + "</p>";

    // Do not disclose whether a subaccount exists or change it for ordinary players.
    if (!ChallengeAdminAccess.isVerified(session)) {
      response.getWriter().write(requestReceived);
      return;
    }
    Cookie[] cookies = request.getCookies();
    Cookie csrfCookie = cookies == null ? null : Validate.getToken(cookies);
    if (!Validate.validateTokens(csrfCookie, request.getParameter("csrfToken"))) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    String email = request.getParameter("subEmail");
    if (email == null || email.length() > 128 || !Validate.isValidEmailAddress(email)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    try (Connection conn =
            Database.getChallengeConnection(
                getServletContext().getRealPath(""), "BrokenAuthAndSessMangChalTwo");
        PreparedStatement find =
            conn.prepareStatement("SELECT userId FROM users WHERE userAddress = ?")) {
      find.setString(1, email);
      int userId;
      try (ResultSet matches = find.executeQuery()) {
        if (!matches.next()) {
          response.getWriter().write(requestReceived);
          return;
        }
        userId = matches.getInt(1);
        if (matches.next()) {
          response.getWriter().write(requestReceived);
          return;
        }
      }

      byte[] random = new byte[24];
      RANDOM.nextBytes(random);
      String newPassword = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
      try (PreparedStatement update =
          conn.prepareStatement(
              "UPDATE users SET userPassword = SHA(?) WHERE userId = ? AND userAddress = ?")) {
        update.setString(1, newPassword);
        update.setInt(2, userId);
        update.setString(3, email);
        if (update.executeUpdate() != 1) {
          response.getWriter().write(requestReceived);
          return;
        }
      }
      if (!conn.getAutoCommit()) {
        conn.commit();
      }
      response
          .getWriter()
          .write(
              "<p>"
                  + bundle.getString("response.changedTo")
                  + " <code>"
                  + Encode.forHtml(newPassword)
                  + "</code></p>");
    } catch (Exception e) {
      log.error("Session Management Two password reset failed", e);
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      response.getWriter().write(errors.getString("error.funky"));
    }
  }
}
