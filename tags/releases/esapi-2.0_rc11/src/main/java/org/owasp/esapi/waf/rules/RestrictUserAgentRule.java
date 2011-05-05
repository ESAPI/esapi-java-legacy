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
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.BlockAction;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

/**
 * This is the Rule subclass executed for &lt;restrict-user-agent&gt; rules.
 * @author Arshan Dabirsiaghi
 *
 */
public class RestrictUserAgentRule extends Rule {

	private static final String USER_AGENT_HEADER = "User-Agent";

	private Pattern allow;
	private Pattern deny;

	public RestrictUserAgentRule(String id, Pattern allow, Pattern deny) {
		this.allow = allow;
		this.deny = deny;
		setId(id);
	}

	public Action check(HttpServletRequest request, InterceptingHTTPServletResponse response, HttpServletResponse httpResponse) {
		
		String userAgent = request.getHeader( USER_AGENT_HEADER );
		
		if ( userAgent == null ) userAgent="";
		
		if ( allow != null ) {
			if ( allow.matcher(userAgent).matches() ) {
				return new DoNothingAction();
			}
		} else if ( deny != null ) {
			if ( ! deny.matcher(userAgent).matches() ) {
				return new DoNothingAction();
			}
		}

		log(request, "Disallowed user agent pattern '" + deny.pattern() + "' found in user agent '" + request.getHeader(USER_AGENT_HEADER) + "'");
	
		/*
		 * If we don't force this to "block", the user will be in an infinite loop, possibly
		 * eating our bandwidth, and in the case of a dread false positive, really piss them
		 * off.
		 * 
		 * Better to just reject.
		 */
		if ( AppGuardianConfiguration.DEFAULT_FAIL_ACTION == AppGuardianConfiguration.REDIRECT ) {
			return new BlockAction();
		}

		return new DefaultAction();
	}

}
