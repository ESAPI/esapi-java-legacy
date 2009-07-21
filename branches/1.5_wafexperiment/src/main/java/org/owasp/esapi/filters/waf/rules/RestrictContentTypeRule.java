package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class RestrictContentTypeRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public RestrictContentTypeRule(String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
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

		log(request, "Disallowed content type '" + deny.pattern() + "' found on URI '" + request.getRequestURI() + "'");
		return new DefaultAction();

	}

}
