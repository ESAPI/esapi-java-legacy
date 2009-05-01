package org.owasp.esapi.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class IPRule extends Rule {

	private Pattern allowedIP;
	private String exactPath;
	private Pattern path;
	private boolean useExactPath = false;

	public IPRule(String id, Pattern allowedIP, Pattern path) {
		this.allowedIP = allowedIP;
		this.path = path;
		this.useExactPath = false;
		setId(id);
	}

	public IPRule(String id, Pattern allowedIP, String exactPath) {
		this.path = null;
		this.exactPath = exactPath;
		this.useExactPath = true;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		String uri = request.getRequestURI();

		if ( (!useExactPath && path.matcher(uri).matches()) ||
			 ( useExactPath && exactPath.equals(uri)) ) {
			if ( ! allowedIP.matcher(request.getRemoteAddr()+"").matches() ) {
				log(request, "IP not allowed to access URI '" + uri + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}
}
