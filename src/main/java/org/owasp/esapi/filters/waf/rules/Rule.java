package org.owasp.esapi.filters.waf.rules;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.owasp.esapi.filters.waf.actions.Action;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public abstract class Rule {

	protected static Logger logger = Logger.getLogger(Rule.class);

	public abstract Action check(
			HttpServletRequest request,
			InterceptingHTTPServletResponse response);

}
