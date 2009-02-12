package org.owasp.esapi.filters.waf.internal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class InterceptingHTTPServletRequest extends HttpServletRequestWrapper {

	public InterceptingHTTPServletRequest(HttpServletRequest request) {
		super(request);
	}

}
