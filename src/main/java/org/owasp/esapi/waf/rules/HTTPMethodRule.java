package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class HTTPMethodRule extends Rule {

	private Pattern allowedMethods;
	private Pattern deniedMethods;
	private Pattern path;

	public HTTPMethodRule(String id, Pattern allowedMethods, Pattern deniedMethods, Pattern path) {
		this.allowedMethods = allowedMethods;
		this.deniedMethods = deniedMethods;
		this.path = path;
		setId(id);
	}

	public Action check(HttpServletRequest request, InterceptingHTTPServletResponse response) {

		/*
		 * If no path is specified, apply rule globally.
		 */

		if ( path == null || path.matcher(request.getRequestURI()).matches() ) {
			/*
			 *	Order allow, deny.
			 */

			if ( allowedMethods != null && allowedMethods.matcher(request.getMethod()).matches() ) {
				return new DoNothingAction();
			}

			if ( deniedMethods != null && deniedMethods.matcher(request.getMethod()).matches() ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

		}

		return new DoNothingAction();
	}

}
