package org.owasp.esapi.filters.waf.rules;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class ReplaceContentRule extends Rule {

	private Pattern pattern;
	private String[] replacements;

	public ReplaceContentRule(Pattern pattern, String[] replacements) {
		this.pattern = pattern;
		this.replacements = replacements;
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		return false;
	}

}
