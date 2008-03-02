package org.owasp.esapi;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionCreateUser {
	
	public static void invoke() throws EnterpriseSecurityException {
		Authenticator auth = ((Authenticator)ESAPI.authenticator());
		HttpServletRequest request = auth.getCurrentRequest();		
		String accountName = request.getParameter("username");
		String rolestring = request.getParameter("roles" );

		if ( accountName != null && rolestring != null) {
			Controller.logger.logSuccess(Logger.SECURITY, "Function: create user " + accountName );
			
			User u = auth.getUser(accountName);
			if ( u == null ) {
				String newPassword = auth.generateStrongPassword();
				request.setAttribute("newPassword", newPassword);
				u = auth.createUser(accountName,newPassword,newPassword);
				if ( !rolestring.equals("") ) {
					String[] rolelist = rolestring.split(",");
					Set roles = new HashSet( Arrays.asList(rolelist) );
					u.setRoles( roles );
				}
			} else {
				// FIXME: create Controller.addMessage();
				request.setAttribute("message", "User already exists" );
			}
		}
		FunctionUpdateUsermap.invoke();
	}
	
}
