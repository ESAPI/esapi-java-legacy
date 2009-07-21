package org.owasp.esapi.waf.rules;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class AuthenticatedRule extends Rule {

	private String sessionAttribute;
	private Pattern path;
	private List<Object> exceptions;

	public AuthenticatedRule(String id, String sessionAttribute, Pattern path, List<Object> exceptions) {
		this.sessionAttribute = sessionAttribute;
		this.path = path;
		this.exceptions = exceptions;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		HttpSession session = request.getSession();

		if ( path != null && ! path.matcher(request.getRequestURI()).matches() ) {
			return new DoNothingAction();
		}

		if ( session != null && session.getAttribute(sessionAttribute) != null ) {

			return new DoNothingAction();

		} else { /* check if it's one of the exceptions */

			Iterator<Object> it = exceptions.iterator();

			while(it.hasNext()) {
				Object o = it.next();
				if ( o instanceof Pattern ) {

					Pattern p = (Pattern)o;
					if ( p.matcher(request.getRequestURI()).matches() ) {
						return new DoNothingAction();
					}

				} else if ( o instanceof String ) {

					if ( request.getRequestURI().equals((String)o)) {
						return new DoNothingAction();
					}

				}
			}
		}

		log(request, "User requested unauthenticated access to URI '" + request.getRequestURI() + "' [querystring="+request.getQueryString()+"]");

		return new DefaultAction();
	}

}
