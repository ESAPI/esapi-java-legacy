package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class RestrictUserAgentRule extends Rule {

	private static final String USER_AGENT_HEADER = "User-Agent";

	private Pattern allow;
	private Pattern deny;

	public RestrictUserAgentRule(Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null ) {
			if ( allow.matcher(request.getHeader(USER_AGENT_HEADER)).matches() ) {
				return true;
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getHeader(USER_AGENT_HEADER)).matches() ) {
				return true;
			}
		}

		return false;
	}

}
