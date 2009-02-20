package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class RestrictContentTypeRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public RestrictContentTypeRule(Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null ) {
			if ( allow.matcher(request.getContentType()).matches() ) {
				return true;
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getContentType()).matches() ) {
				return true;
			}
		}

		return false;

	}

}
