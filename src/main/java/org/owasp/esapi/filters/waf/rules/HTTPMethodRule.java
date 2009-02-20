package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class HTTPMethodRule extends Rule {

	private Pattern allowedMethods;
	private Pattern deniedMethods;
	private Pattern path;

	public HTTPMethodRule(Pattern allowedMethods, Pattern deniedMethods, Pattern path) {
		this.allowedMethods = allowedMethods;
		this.deniedMethods = deniedMethods;
		this.path = path;
	}

	public boolean check(InterceptingHTTPServletRequest request, InterceptingHTTPServletResponse response) {

		/*
		 * If no path is specified, apply rule globally.
		 */

		if ( path != null || path.matcher(request.getRequestURI()).matches() ) {
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
		}

		return false;
	}

}
