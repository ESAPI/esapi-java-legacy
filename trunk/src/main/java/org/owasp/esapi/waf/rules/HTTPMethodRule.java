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
		String uri = request.getRequestURI();
		String method = request.getMethod();

		if ( path == null || path.matcher(uri).matches() ) {
			/*
			 *	Order allow, deny.
			 */

			if ( allowedMethods != null && allowedMethods.matcher(method).matches() ) {
				return new DoNothingAction();
			} else if ( allowedMethods != null ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

			if ( deniedMethods != null && deniedMethods.matcher(method).matches() ) {
				log(request,"Disallowed HTTP method '" + request.getMethod() + "' found for URL: " + request.getRequestURL());
				return new DefaultAction();
			}

		}

		return new DoNothingAction();
	}

}
