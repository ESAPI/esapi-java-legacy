package org.owasp.esapi;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionLockUser {

	public static void invoke() throws EnterpriseSecurityException {
		Authenticator auth = ((Authenticator)ESAPI.authenticator());
		HttpServletRequest request = auth.getCurrentRequest();		
		AccessReferenceMap arm = FunctionUpdateUsermap.invoke();
		String param = request.getParameter("user");
		String accountName = (String)arm.getDirectReference(param);
		Controller.logger.logSuccess(Logger.SECURITY, "Function: lock user " + accountName );
		auth.getUser(accountName).lock();
	}

}
