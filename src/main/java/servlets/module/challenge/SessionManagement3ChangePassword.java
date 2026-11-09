package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
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
 * Session Management Challenge Three - Change Password This is a level function - DOES NOT RETURN
 * KEY <br>
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
public class SessionManagement3ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement3ChangePassword.class);
  private static String levelName = "Session Management Challenge Three (Change Password)";
  public static String levelHash =
      "b467dbe3cd61babc0ec599fd0c67e359e6fe04e8cdc618d537808cbb693fee8a";

  // private static String levelResult = ""; //This Servlet does not return a result

  /**
   * Function used by Session Management Challenge Three to change the password of the submitted
   * guest12 demonstration account; client cookies do not select the account
   *
   * @param newPassword the password which to use to update an accounts password
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement3", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      log.debug(levelName + " - Change Password - Servlet");
      try {
        log.debug("Getting Challenge Parameters");
        Object passNewObj = request.getParameter("newPassword");
        // The password form operates on the guest12 demonstration account. A client cookie
        // cannot choose a different account, particularly an administrator account.
        String subName = "guest12";
        String subNewPass = new String();
        if (passNewObj != null) {
          subNewPass = (String) passNewObj;
        }

        if (subNewPass.length() >= 6) {
          log.debug("Getting ApplicationRoot");
          String ApplicationRoot = getServletContext().getRealPath("");

          Connection conn =
              Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalThree");
          log.debug("Changing password for user: " + subName);
          log.debug("Changing password to: " + subNewPass);
          PreparedStatement callstmt;

          callstmt =
              conn.prepareStatement(
                  "UPDATE users SET userPassword = SHA(?) WHERE userName = ? AND userRole = 'guest'");
          callstmt.setString(1, subNewPass);
          callstmt.setString(2, subName);
          log.debug("Executing changePassword");
          int updated = callstmt.executeUpdate();

          log.debug("Committing changes made to database");
          callstmt = conn.prepareStatement("COMMIT");
          callstmt.execute();
          log.debug("Changes committed.");

          htmlOutput =
              "<p>" + bundle.getString(updated == 1 ? "reset.password" : "reset.failed") + "</p>";
        } else {
          log.debug("invalid password submitted: " + subNewPass);
          htmlOutput = "<p>" + bundle.getString("reset.failed") + "</p>";
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - Change Password - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
