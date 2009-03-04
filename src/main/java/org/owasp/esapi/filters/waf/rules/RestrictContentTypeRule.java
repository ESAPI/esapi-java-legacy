package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DefaultAction;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class RestrictContentTypeRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public RestrictContentTypeRule(Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		/* can't check content type if it's not available */
		if ( request.getContentType() == null ) {
			return new DoNothingAction();
		}

		if ( allow != null ) {
			if ( allow.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
		}

		return new DefaultAction();

	}

}
