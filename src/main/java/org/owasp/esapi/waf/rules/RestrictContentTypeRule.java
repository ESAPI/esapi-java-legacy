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

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class RestrictContentTypeRule extends Rule {

	private Pattern allow;
	private Pattern deny;

	public RestrictContentTypeRule(String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response) {

		/* can't check content type if it's not available */
		if ( request.getContentType() == null ) {
			return new DoNothingAction();
		}

		if ( allow != null ) {
			if ( allow.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on allow pattern '" + allow.pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() +"')");
		} else if ( deny != null ) {
			if ( ! deny.matcher(request.getContentType()).matches() ) {
				return new DoNothingAction();
			}
			log(request, "Disallowed content type based on deny pattern '" + deny.pattern() + "' found on URI '" + request.getRequestURI() + "' (value was '" + request.getContentType() + ")'");
		}


		return new DefaultAction();

	}

}
