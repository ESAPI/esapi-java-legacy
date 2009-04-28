package org.owasp.esapi.waf.rules;

import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class AddSecureFlagRule extends Rule {

	private List<Pattern> name;

	public AddSecureFlagRule(String id, List<Pattern> name) {
		this.name = name;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {
		DoNothingAction action = new DoNothingAction();

		return action;
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
