package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class PathExtensionRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public PathExtensionRule (String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( allow != null && allow.matcher(request.getRequestURI()).matches() ) {
			return new DoNothingAction();
		} else if ( deny != null && deny.matcher(request.getRequestURI()).matches() ) {

			log(request, "Disallowed extension pattern '" + deny.pattern() + "' found on URI '" + request.getRequestURI() + "'");

			return new DefaultAction();
		}

		return new DoNothingAction();
	}

}
