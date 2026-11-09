package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Administrator-assisted Session Management Five password reset <br>
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
public class SessionManagement5ChangePassword extends HttpServlet {
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5ChangePassword.class);

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession session = request.getSession(false);
    if (!Validate.validateSession(session) || !ChallengeAdminAccess.isVerified(session)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    if (!Validate.validateTokens(
        Validate.getToken(request.getCookies()), request.getParameter("csrfToken"))) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    Locale locale = new Locale(Validate.validateLanguage(session));
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement5", locale);
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    response.setContentType("text/html;charset=UTF-8");
    String userName = request.getParameter("userName");
    String newPassword = request.getParameter("newPassword");
    String token = request.getParameter("resetPasswordToken");
    if (userName == null || userName.isBlank() || userName.length() > 32 || newPassword == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    if (newPassword.length() < 12) {
      response.getWriter().write("<p>" + bundle.getString("changePass.failure") + "</p>");
      return;
    }
    if (!SessionManagement5ResetToken.consume(session, userName, token)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    try (Connection conn =
            Database.getChallengeConnection(
                getServletContext().getRealPath(""), "BrokenAuthAndSessMangChalFive");
        PreparedStatement update =
            conn.prepareStatement("UPDATE users SET userPassword = SHA(?) WHERE userName = ?")) {
      update.setString(1, newPassword);
      update.setString(2, userName);
      int changed = update.executeUpdate();
      if (!conn.getAutoCommit()) {
        conn.commit();
      }
      response
          .getWriter()
          .write(
              "<p>"
                  + bundle.getString(changed == 1 ? "changePass.success" : "changePass.failure")
                  + "</p>");
    } catch (Exception e) {
      log.error("Session 5 password reset failed", e);
      response.getWriter().write(errors.getString("error.funky"));
    }
  }
}
