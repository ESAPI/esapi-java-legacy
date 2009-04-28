package org.owasp.esapi.waf.rules;

import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.actions.RedirectAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class EnforceHTTPSRule extends Rule {

	private Pattern path;
	private List<Object> exceptions;
	private String action;

	/*
	 * action = [ redirect | block ] [=default (redirect will redirect to error page]
	 */

	public EnforceHTTPSRule(String id, Pattern path, List<Object> exceptions, String action) {
		this.path = path;
		this.exceptions = exceptions;
		this.action = action;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( ! request.isSecure() ) {

			if ( path.matcher(request.getRequestURI()).matches() ) {

				Iterator<Object> it = exceptions.iterator();

				while(it.hasNext()){

					Object o = it.next();

					if ( o instanceof String ) {
						if ( ((String)o).equalsIgnoreCase(request.getRequestURI()) ) {
							return new DoNothingAction();
						}
					} else if ( o instanceof Pattern ) {
						if ( ((Pattern)o).matcher(request.getRequestURI()).matches() ) {
							return new DoNothingAction();
						}
					}

				}

				log(request,"Insecure request to resource detected in URL: '" + request.getRequestURL() + "'");

				if ( "redirect".equals(action) ) {
					RedirectAction ra = new RedirectAction();
					ra.setRedirectURL(request.getRequestURL().toString().replaceFirst("http", "https"));
					return ra;
				}

				return new DefaultAction();

			}
		}

		return new DoNothingAction();

	}
}
