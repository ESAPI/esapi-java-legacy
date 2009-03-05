package org.owasp.esapi.filters.waf.rules;

import java.util.Enumeration;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.filters.waf.actions.Action;
import org.owasp.esapi.filters.waf.actions.DefaultAction;
import org.owasp.esapi.filters.waf.actions.DoNothingAction;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class GeneralAttackSignatureRule extends Rule {

	private Pattern signature;

	public GeneralAttackSignatureRule(String id, Pattern signature) {
		this.signature = signature;
		setId(id);
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;
		Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			if ( signature.matcher(request.getDictionaryParameter(param)).matches() ) {
				log(request,"General attack signature detected in parameter '" + param + "' value '" + request.getDictionaryParameter(param) + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}

}
