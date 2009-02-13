package org.owasp.esapi.filters.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class DetectOutboundContentRule extends Rule {

	private List<Pattern> patterns;

	public boolean check(InterceptingHTTPServletRequest request,
			HttpServletResponse response) {

		byte[] bytes = ((InterceptingHTTPServletResponse)response).getInterceptingServletOutputStream().getResponseBytes();

		/*
		 * Depending on the encoding, search through the bytes
		 * for the patterns. If they all match, return a FAIL!
		 */

		return true;
	}

}
