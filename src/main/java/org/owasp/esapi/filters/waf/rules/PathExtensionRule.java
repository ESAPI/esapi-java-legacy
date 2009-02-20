package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class PathExtensionRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public PathExtensionRule (Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null && allow.matcher(request.getRequestURI()).matches() ) {
			return true;
		} else if ( deny != null && deny.matcher(request.getRequestURI()).matches() ) {
			return true;
		}

		return false;
	}

}
