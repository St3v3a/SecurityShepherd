package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
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
 * Issues a short-lived, one-use subaccount reset token to a freshly confirmed platform admin.
 *
 * <p><br>
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
public class SessionManagement5SetToken extends HttpServlet {
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5SetToken.class);
  private static final String LEVEL_HASH = SessionManagement5.levelHash;

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
            "i18n.servlets.challenges.sessionManagement.sessionManagement5", locale);
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    response.setContentType("text/html;charset=UTF-8");

    // Keep the public response independent of whether the requested subaccount exists.
    if (!ChallengeAdminAccess.isVerified(session)) {
      response.getWriter().write("<p>" + bundle.getString("setToken.requestReceived") + "</p>");
      return;
    }
    String csrfToken = request.getParameter("csrfToken");
    if (!Validate.validateTokens(Validate.getToken(request.getCookies()), csrfToken)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    String userName = request.getParameter("subUserName");
    if (userName == null || userName.isBlank() || userName.length() > 32) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST);
      return;
    }

    try (Connection conn =
            Database.getChallengeConnection(
                getServletContext().getRealPath(""), "BrokenAuthAndSessMangChalFive");
        PreparedStatement query =
            conn.prepareStatement("SELECT userName FROM users WHERE userName = ?")) {
      query.setString(1, userName);
      try (ResultSet result = query.executeQuery()) {
        if (!result.next()) {
          response.getWriter().write("<p>" + bundle.getString("setToken.requestReceived") + "</p>");
          return;
        }
      }
      String token = SessionManagement5ResetToken.issue(session, userName);
      response
          .getWriter()
          .write(
              "<p>"
                  + bundle.getString("setToken.adminReady")
                  + "</p><form method=\"post\" action=\""
                  + Encode.forHtmlAttribute(request.getContextPath())
                  + "/challenges/"
                  + LEVEL_HASH
                  + "ChangePass\"><input type=\"hidden\" name=\"userName\" value=\""
                  + Encode.forHtmlAttribute(userName)
                  + "\" /><input type=\"hidden\" name=\"resetPasswordToken\" value=\""
                  + Encode.forHtmlAttribute(token)
                  + "\" /><input type=\"hidden\" name=\"csrfToken\" value=\""
                  + Encode.forHtmlAttribute(csrfToken)
                  + "\" /><label>New password <input type=\"password\" name=\"newPassword\" minlength=\"12\" required /></label>"
                  + "<button type=\"submit\">Reset subaccount password</button></form>");
    } catch (Exception e) {
      log.error("Could not issue Session 5 reset token", e);
      response.getWriter().write(errors.getString("error.funky"));
    }
  }
}
