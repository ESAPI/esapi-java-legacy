package org.owasp.esapi;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionEnableUser {
	
	public static void invoke() throws EnterpriseSecurityException {
		Authenticator auth = ((Authenticator)ESAPI.authenticator());
		HttpServletRequest request = auth.getCurrentRequest();		
		AccessReferenceMap arm = FunctionUpdateUsermap.invoke();
		String param = request.getParameter("user");
		String accountName = (String)arm.getDirectReference(param);
		Controller.logger.logSuccess(Logger.SECURITY, "Function: enable user " + accountName );
		auth.getUser(accountName).enable();
	}
	

}
