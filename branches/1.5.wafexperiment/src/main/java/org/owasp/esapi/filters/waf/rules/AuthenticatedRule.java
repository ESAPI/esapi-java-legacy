package org.owasp.esapi.filters.waf.rules;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;

public class AuthenticatedRule extends Rule {

	private String sessionAttribute;

	public AuthenticatedRule(String sessionAttribute) {
		this.sessionAttribute = sessionAttribute;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			HttpServletResponse response) {

		HttpSession session = request.getSession();

		if ( session != null && session.getAttribute(sessionAttribute) != null ) {
			return true;
		}

		return false;
	}

}
