package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
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
 * Failure to Restrict URL Access Challenge 3 (UserList) <br>
 * <br>
 * This class is the target functionality for the challenge. The information required to find this
 * admin function is contained in the javascript of the JSP page associated with the level. This
 * level returns a user specific key. <br>
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
public class UrlAccess3UserList extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(UrlAccess3UserList.class);
  private static String levelName = "URL Access 3 (UserList)";

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();

      try {
        String ApplicationRoot = getServletContext().getRealPath("");
        String query =
            ChallengeAdminAccess.isVerified(ses)
                ? "SELECT userName FROM users WHERE userRole IN ('admin', 'superadmin') OR userName = ?"
                : "SELECT userName FROM users WHERE userName = ?";
        try (Connection conn = Database.getChallengeConnection(ApplicationRoot, "UrlAccessThree");
            PreparedStatement callstmt = conn.prepareStatement(query)) {
          callstmt.setString(1, "aGuest");
          log.debug("Getting User List");
          try (ResultSet rs = callstmt.executeQuery()) {
            while (rs.next()) {
              htmlOutput += Encode.forHtml(rs.getString(1)) + "<br>";
            }
          }
        }
      } catch (Exception e) {
        htmlOutput = new String(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
      log.debug("Outputting HTML");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
