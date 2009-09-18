/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
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
		String uri = request.getRequestURI();

		if ( path != null && ! path.matcher(uri).matches() ) {
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
					if ( p.matcher(uri).matches() ) {
						return new DoNothingAction();
					}

				} else if ( o instanceof String ) {

					if ( uri.equals((String)o)) {
						return new DoNothingAction();
					}

				}
			}
		}

		log(request, "User requested unauthenticated access to URI '" + request.getRequestURI() + "' [querystring="+request.getQueryString()+"]");

		return new DefaultAction();
	}

}
