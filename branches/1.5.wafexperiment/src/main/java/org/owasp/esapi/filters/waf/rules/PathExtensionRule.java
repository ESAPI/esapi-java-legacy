package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DefaultAction;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class PathExtensionRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public PathExtensionRule (Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null && allow.matcher(request.getRequestURI()).matches() ) {
			return new DoNothingAction();
		} else if ( deny != null && deny.matcher(request.getRequestURI()).matches() ) {
			return new DefaultAction();
		}

		return new DoNothingAction();
	}

}
