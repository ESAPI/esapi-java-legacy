package org.owasp.esapi.filters.waf.internal;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

public class InterceptingHTTPServletResponse extends HttpServletResponseWrapper {

	public InterceptingHTTPServletResponse(HttpServletResponse response) {
		super(response);
	}

}
