package org.owasp.esapi.filters.waf.rules;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AuthenticatedRule extends Rule {

	private String sessionAttribute;

	public AuthenticatedRule(String sessionAttribute) {
		this.sessionAttribute = sessionAttribute;
	}

	public boolean check(HttpServletRequest request,
			HttpServletResponse response) {

		HttpSession session = request.getSession();

		if ( session != null && session.getAttribute(sessionAttribute) != null ) {
			return true;
		}

		return false;
	}

}
