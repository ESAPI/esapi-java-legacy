package org.owasp.esapi.filters.waf.rules;

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class SimpleVirtualPatchRule extends Rule {

	private static final String REQUEST_PARAMETERS = "request.parameters.";
	private static final String REQUEST_HEADERS = "request.headers.";

	private Pattern path;
	private String variable;
	private Pattern valid;
	private String id;
	private String message;

	public SimpleVirtualPatchRule(String id, Pattern path, String variable, Pattern valid, String message) {
		this.id = id;
		this.path = path;
		this.variable = variable;
		this.valid = valid;
		this.message = message;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( path.matcher(request.getRequestURI()).matches() ) {

			/*
			 * Decide which parameters/headers to act on.
			 */
			String target = null;
			Enumeration en = null;
			boolean parameter = true;

			if ( variable.startsWith(REQUEST_PARAMETERS)) {

				target = variable.substring(REQUEST_PARAMETERS.length());
				en = request.getParameterNames();

			} else if ( variable.startsWith(REQUEST_HEADERS) ) {

				parameter = false;
				target = variable.substring(REQUEST_HEADERS.length());
				en = request.getHeaderNames();

			} else {
				/*
				 * User put in a "variable" attribute in the rule - didn't start with request.parameters
				 * or request.headers.
				 */
				return false;
			}

			/*
			 * If it contains a regex character, it's a regex. Loop through elements and grab any matches.
			 */
			if ( target.contains("*") || target.contains("?") ) {

				target = target.replaceAll("*", ".*");
				Pattern p = Pattern.compile(target);
				while (en.hasMoreElements() ) {
					String s = (String)en.nextElement();
					String value = null;
					if ( p.matcher(target).matches() ) {
						if ( parameter ) {
							value = request.getDictionaryParameter(s);
						} else {
							value = request.getHeader(s);
						}
						if ( ! valid.matcher(value).matches() ) {
							return false;
						}
					}
				}

			} else {

				if ( parameter ) {
					return valid.matcher(request.getDictionaryParameter(target)).matches();
				} else {
					return valid.matcher(request.getHeader(target)).matches();
				}
			}

		}

		return false;
	}

}
