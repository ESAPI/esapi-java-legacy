package org.owasp.esapi.filters.waf.rules;

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class GeneralAttackSignatureRule extends Rule {

	private Pattern signature;

	public GeneralAttackSignatureRule(Pattern signature) {
		this.signature = signature;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			if ( signature.matcher(request.getDictionaryParameter(param)).matches() ) {
				return false;
			}
		}

		return true;
	}


}
