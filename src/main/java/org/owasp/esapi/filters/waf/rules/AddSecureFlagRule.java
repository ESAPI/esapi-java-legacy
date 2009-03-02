package org.owasp.esapi.filters.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class AddSecureFlagRule extends Rule {

	private List<Pattern> name;

	public AddSecureFlagRule(List<Pattern> name) {
		this.name = name;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {
		return true;
	}

	public boolean doesCookieMatch(String cookieName) {

		for(int i=0;i<name.size();i++) {
			Pattern p = name.get(i);
			if ( p.matcher(cookieName).matches() ) {
				return true;
			}
		}

		return false;
	}

}
