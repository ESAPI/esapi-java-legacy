package org.owasp.esapi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.errors.EnterpriseSecurityException;

public class FunctionUpdateUsermap {

	public static AccessReferenceMap invoke() throws EnterpriseSecurityException {
		Authenticator auth = ((Authenticator)ESAPI.authenticator());
		HttpServletRequest request = auth.getCurrentRequest();
		HttpSession session = request.getSession();
		AccessReferenceMap arm = (AccessReferenceMap) session.getAttribute("usermap" );
		if ( arm == null ) {
			arm = new AccessReferenceMap();
			request.getSession().setAttribute( "usermap", arm );
		}
		arm.update(auth.getUserNames());
		return arm;
	}

}
