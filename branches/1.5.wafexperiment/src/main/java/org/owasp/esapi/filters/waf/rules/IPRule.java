package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( (!useExactPath && path.matcher(request.getRequestURI()).matches()) ||
			 ( useExactPath && exactPath.equals(request.getRequestURI())) ) {
			if ( ! allowedIP.matcher(request.getRemoteAddr()).matches() ) {
				return false;
			}
		}

		return true;
	}

}
