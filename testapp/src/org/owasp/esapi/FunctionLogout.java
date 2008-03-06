package org.owasp.esapi;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionLogout {

	public static void invoke() throws EnterpriseSecurityException {
		Controller.logger.logSuccess(Logger.SECURITY, "Function: logout" );
		Authenticator auth = (Authenticator)ESAPI.authenticator();
		auth.getCurrentRequest().setAttribute("message", "User logged out" );
		auth.logout();
	}

}
