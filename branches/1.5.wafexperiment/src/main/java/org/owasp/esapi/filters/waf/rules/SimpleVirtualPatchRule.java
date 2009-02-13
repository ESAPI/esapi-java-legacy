package org.owasp.esapi.filters.waf.rules;

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;

public class SimpleVirtualPatchRule extends Rule {

	private Pattern path;
	private Pattern parameters;
	private Pattern exceptions;
	private Pattern signature;

	public SimpleVirtualPatchRule(Pattern path, Pattern parameters, Pattern exceptions, Pattern signature) {
		this.path = path;
		this.parameters = parameters;
		this.exceptions = exceptions;
		this.signature = signature;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			HttpServletResponse response) {

		if ( path.matcher(request.getRequestURI()).matches() ) {

			/*
			 * Go through each parameter except those that match the "exceptions"
			 * and test if they match the signature.
			 */
			Enumeration e = request.getParameterNames();

			while(e.hasMoreElements()) {
				String param = (String)e.nextElement();
				if ( parameters.matcher(param).matches() ) {
					if ( exceptions == null || ! exceptions.matcher(param).matches() ) {
						if ( signature.matcher(request.getDictionaryParameter(param)).matches() ) {
							return false;
						}
					}
				}
			}

		}

		return true;
	}

}
