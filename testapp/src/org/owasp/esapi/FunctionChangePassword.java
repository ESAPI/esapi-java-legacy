package org.owasp.esapi;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionChangePassword {

	public static void invoke() throws EnterpriseSecurityException {
		Authenticator auth = ((Authenticator)ESAPI.authenticator());
		HttpServletRequest request = auth.getCurrentRequest();		
		AccessReferenceMap arm = FunctionUpdateUsermap.invoke();
		// FIXME: add parameter set validation...
		// Validator.isValidParameterSet( required, optional, actual );
		String param = request.getParameter("user");
		String accountName = (String)arm.getDirectReference(param);
		Controller.logger.logSuccess(Logger.SECURITY, "Function: change password: " + accountName );
		String newPassword = auth.getUser(accountName).resetPassword();
		request.setAttribute("newPassword", newPassword);
	}

}