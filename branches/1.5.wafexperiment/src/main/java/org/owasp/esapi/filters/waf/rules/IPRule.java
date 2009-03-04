package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DefaultAction;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class IPRule extends Rule {

	private Pattern allowedIP;
	private String exactPath;
	private Pattern path;
	private boolean useExactPath = false;

	public IPRule(Pattern allowedIP, Pattern path) {
		this.allowedIP = allowedIP;
		this.path = path;
		this.useExactPath = false;
	}

	public IPRule(Pattern allowedIP, String exactPath) {
		this.path = null;
		this.exactPath = exactPath;
		this.useExactPath = true;
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( (!useExactPath && path.matcher(request.getRequestURI()).matches()) ||
			 ( useExactPath && exactPath.equals(request.getRequestURI())) ) {
			if ( ! allowedIP.matcher(request.getRemoteAddr()).matches() ) {
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}
}
