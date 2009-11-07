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
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class IPRule extends Rule {

	private Pattern allowedIP;
	private String exactPath;
	private Pattern path;
	private boolean useExactPath = false;
	private String ipHeader;

	public IPRule(String id, Pattern allowedIP, Pattern path, String ipHeader) {
		this.allowedIP = allowedIP;
		this.path = path;
		this.useExactPath = false;
		this.ipHeader = ipHeader;
		setId(id);
	}

	public IPRule(String id, Pattern allowedIP, String exactPath) {
		this.path = null;
		this.exactPath = exactPath;
		this.useExactPath = true;
		setId(id);
	}

	public Action check(HttpServletRequest request,
			InterceptingHTTPServletResponse response, 
			HttpServletResponse httpResponse) {

		String uri = request.getRequestURI();

		if ( (!useExactPath && path.matcher(uri).matches()) ||
			 ( useExactPath && exactPath.equals(uri)) ) {
			
			String sourceIP = request.getRemoteAddr() + "";
			
			if ( ipHeader != null ) {
				sourceIP = request.getHeader(ipHeader);
			}
			
			if ( ! allowedIP.matcher(sourceIP).matches() ) {
				log(request, "IP not allowed to access URI '" + uri + "'");
				return new DefaultAction();
			}
		}

		return new DoNothingAction();
	}
}
