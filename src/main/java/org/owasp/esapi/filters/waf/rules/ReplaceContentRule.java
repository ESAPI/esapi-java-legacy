package org.owasp.esapi.filters.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class ReplaceContentRule extends Rule {

	private Pattern pattern;
	private List<String> replacements;

	public ReplaceContentRule(Pattern pattern, List<String> replacements) {
		this.pattern = pattern;
		this.replacements = replacements;
	}

	/*
	 * Use regular expressions with capturing parentheses to perform replacement.
	 */

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		return new DoNothingAction();
	}

}
