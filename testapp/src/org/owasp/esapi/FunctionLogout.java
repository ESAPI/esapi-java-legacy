package org.owasp.esapi;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionLogout {

	public static void invoke() throws EnterpriseSecurityException {
		Controller.logger.logSuccess(Logger.SECURITY, "Function: logout" );
		ESAPI.authenticator().logout();
	}

}
