package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class RestrictUserAgentRule extends Rule {

	private static final String USER_AGENT_HEADER = "User-Agent";

	private Pattern allow;
	private Pattern deny;

	public RestrictUserAgentRule(String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
	}

	public Action check(HttpServletRequest request, InterceptingHTTPServletResponse response) {
		String userAgent = request.getHeader( USER_AGENT_HEADER );
		if ( userAgent == null ) userAgent="";
		
		if ( allow != null ) {
			if ( allow.matcher(userAgent).matches() ) {
				return new DoNothingAction();
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(userAgent).matches() ) {
				return new DoNothingAction();
			}
		}

		log(request, "Disallowed user agent pattern '" + deny.pattern() + "' found in user agent '" + request.getHeader(USER_AGENT_HEADER) + "'");
		return new DefaultAction();
	}

}
