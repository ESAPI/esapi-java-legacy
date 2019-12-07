package org.owasp.esapi.logging.appender;

import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;

public class ClientInfoSupplier implements Supplier <String> {
	private static final String ESAPI_SESSION_ATTR = "ESAPI_SESSION";
	private static final int ESAPI_SESSION_RAND_MIN = 0;
	private static final int ESAPI_SESSION_RAND_MAX = 1000000;

	private static final String USER_INFO_FORMAT = "%s:%s@%s";

	private boolean logUserInfo = true;

	@Override
	public String get() {
		String userInfo = "";
		// log user information - username:session@ipaddr
		User user = ESAPI.authenticator().getCurrentUser();
		if (logUserInfo && user != null) {
			HttpServletRequest request = ESAPI.currentRequest();
			// create a random session number for the user to represent the user's 'session', if it doesn't exist already
			String sid = "";
			if (request != null) {
				HttpSession session = request.getSession(false);
				if (session != null) {
					sid = (String) session.getAttribute(ESAPI_SESSION_ATTR);
					// if there is no session ID for the user yet, we create one and store it in the user's session
					if (sid == null) {
						sid = "" + ESAPI.randomizer().getRandomInteger(ESAPI_SESSION_RAND_MIN, ESAPI_SESSION_RAND_MAX);
						session.setAttribute(ESAPI_SESSION_ATTR, sid);
					}
				}
			}

			userInfo = String.format(USER_INFO_FORMAT, user.getAccountName(), sid, user.getLastHostAddress());
		}
		return userInfo;
	}

	public void setLogUserInfo(boolean log) {
		this.logUserInfo = log;
	}

}
