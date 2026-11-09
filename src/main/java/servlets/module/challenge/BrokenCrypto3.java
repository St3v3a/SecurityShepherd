package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
 * Authenticated decryption example for Cryptography Challenge Three. <br>
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
public class BrokenCrypto3 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto3.class);
  private static String levelName = "Broken Crypto Challenge 3";
  public static String levelHash =
      "2da053b4afb1530a500120a49a14d422ea56705a7e3fc405a77bc269948ccae1";
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String SESSION_KEY = BrokenCrypto3.class.getName() + ".key";
  private static final String TOKEN_PREFIX = "v1.";
  private static final String EXAMPLE_TEXT = "Authenticated encryption protects this example.";
  private static final int NONCE_LENGTH = 12;
  private static final int KEY_LENGTH = 32;

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));

    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      String htmlOutput = new String();

      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
      try {
        String userData = request.getParameter("userData");
        String decryptedUserData = decrypt(userData, ses);

        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult")
                + "</h2><p>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult.message")
                + "<br/><br/><em>"
                + Encode.forHtml(decryptedUserData)
                + "</em></p>";
      } catch (GeneralSecurityException e) {
        log.debug(levelName + " - rejected invalid ciphertext");
        htmlOutput = errors.getString("error.funky");
      } catch (Exception e) {
        log.fatal(levelName + " - " + e.toString());
        htmlOutput = errors.getString("error.funky");
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /** Creates a harmless, authenticated example for the current session. */
  public static String exampleCiphertext(HttpSession session) {
    try {
      byte[] nonce = new byte[NONCE_LENGTH];
      RANDOM.nextBytes(nonce);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(getOrCreateKey(session), "AES"),
          new GCMParameterSpec(128, nonce));
      byte[] encrypted = cipher.doFinal(EXAMPLE_TEXT.getBytes(StandardCharsets.UTF_8));
      byte[] payload = new byte[nonce.length + encrypted.length];
      System.arraycopy(nonce, 0, payload, 0, nonce.length);
      System.arraycopy(encrypted, 0, payload, nonce.length, encrypted.length);
      return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Could not create encrypted example", e);
    }
  }

  /** Decrypts only authenticated ciphertext issued for the current session. */
  public static String decrypt(String token, HttpSession session) throws GeneralSecurityException {
    if (token == null || !token.startsWith(TOKEN_PREFIX) || token.length() > 4096) {
      throw new GeneralSecurityException("Unsupported ciphertext");
    }
    byte[] payload;
    try {
      payload = Base64.getUrlDecoder().decode(token.substring(TOKEN_PREFIX.length()));
    } catch (IllegalArgumentException e) {
      throw new GeneralSecurityException("Invalid ciphertext encoding", e);
    }
    if (payload.length < NONCE_LENGTH + 16) {
      throw new GeneralSecurityException("Ciphertext is too short");
    }
    Object key = session.getAttribute(SESSION_KEY);
    if (!(key instanceof byte[]) || ((byte[]) key).length != KEY_LENGTH) {
      throw new GeneralSecurityException("No key for this session");
    }
    byte[] nonce = Arrays.copyOfRange(payload, 0, NONCE_LENGTH);
    byte[] encrypted = Arrays.copyOfRange(payload, NONCE_LENGTH, payload.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec((byte[]) key, "AES"),
        new GCMParameterSpec(128, nonce));
    return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
  }

  private static byte[] getOrCreateKey(HttpSession session) {
    synchronized (session) {
      Object key = session.getAttribute(SESSION_KEY);
      if (!(key instanceof byte[]) || ((byte[]) key).length != KEY_LENGTH) {
        byte[] newKey = new byte[KEY_LENGTH];
        RANDOM.nextBytes(newKey);
        session.setAttribute(SESSION_KEY, newKey);
        return newKey;
      }
      return (byte[]) key;
    }
  }
}
