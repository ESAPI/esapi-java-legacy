package org.owasp.esapi.filters.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class HTTPMethodRule extends Rule {

	private Pattern allowedMethods;
	private Pattern deniedMethods;


	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		/*
		 *	Order allow, deny.
		 */

		if ( allowedMethods != null && allowedMethods.matcher(request.getMethod()).matches() ) {
			return true;
		}

		if ( deniedMethods != null && deniedMethods.matcher(request.getMethod()).matches() ) {
			return false;
		}

		if ( allowedMethods == null && deniedMethods == null ) {
			return true;
		}

		return false;
	}

	public HTTPMethodRule(Pattern allowedMethods, Pattern deniedMethods) {
		this.allowedMethods = allowedMethods;
		this.deniedMethods = deniedMethods;
	}
}
