package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DefaultAction;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
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

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null ) {
			if ( allow.matcher(request.getHeader(USER_AGENT_HEADER)).matches() ) {
				return new DoNothingAction();
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getHeader(USER_AGENT_HEADER)).matches() ) {
				return new DoNothingAction();
			}
		}

		return new DefaultAction();
	}

}
