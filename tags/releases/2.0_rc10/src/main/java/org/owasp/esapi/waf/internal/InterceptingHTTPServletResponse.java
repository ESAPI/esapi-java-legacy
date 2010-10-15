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
package org.owasp.esapi.waf.internal;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.esapi.waf.rules.AddHTTPOnlyFlagRule;
import org.owasp.esapi.waf.rules.AddSecureFlagRule;
import org.owasp.esapi.waf.rules.Rule;

/**
 * The wrapper for the HttpServletResponse object which will be passed to the application
 * being protected by the WAF. It contains logic for the response building API in order
 * to allow the WAF rules regarding responses to work. Much of the work is delegated to
 * other classes, especially InterceptingServletOutputStream
 * 
 * @author Arshan Dabirsiaghi
 *
 */
public class InterceptingHTTPServletResponse extends HttpServletResponseWrapper {

	private InterceptingPrintWriter ipw;
	private InterceptingServletOutputStream isos;
	private String contentType;

	private List<AddSecureFlagRule> addSecureFlagRules = null;
	private List<AddHTTPOnlyFlagRule> addHTTPOnlyFlagRules = null;
	private boolean alreadyCalledWriter = false;
	private boolean alreadyCalledOutputStream = false;

	public InterceptingHTTPServletResponse(HttpServletResponse response, boolean buffering, List<Rule> cookieRules) throws IOException {

		super(response);
		
		this.contentType = response.getContentType();
		
		this.isos = new InterceptingServletOutputStream(response.getOutputStream(), buffering);
		this.ipw = new InterceptingPrintWriter(new PrintWriter(isos));

		addSecureFlagRules = new ArrayList<AddSecureFlagRule>();
		addHTTPOnlyFlagRules = new ArrayList<AddHTTPOnlyFlagRule>();

		for(int i=0;i<cookieRules.size();i++) {
			Rule r = cookieRules.get(i);
			if ( r instanceof AddSecureFlagRule ) {
				addSecureFlagRules.add((AddSecureFlagRule)r);
			} else if ( r instanceof AddHTTPOnlyFlagRule ) {
				addHTTPOnlyFlagRules.add((AddHTTPOnlyFlagRule)r);
			}
		}
	}

	public boolean isUsingWriter() {
		return alreadyCalledWriter;
	}

	public InterceptingServletOutputStream getInterceptingServletOutputStream() {
		return isos;
	}

	public ServletOutputStream getOutputStream() throws IllegalStateException, IOException {
		if ( alreadyCalledWriter == true ) {
			throw new IllegalStateException();
		}

		alreadyCalledOutputStream = true;

		return isos;
    }

	public PrintWriter getWriter() throws IOException {
		if ( alreadyCalledOutputStream == true ) {
			throw new IllegalStateException();
		}
		alreadyCalledWriter = true;

		return ipw;
	}

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String s) {
    	contentType = s;
    }

    public void flush() {
    	ipw.flush();
    }

    public void commit() throws IOException {

    	if ( alreadyCalledWriter ) {
    		ipw.flush();
    	}

    	isos.commit();
    }

    public void addCookie(Cookie cookie) {
    	addCookie(cookie, cookie.getMaxAge()<=0);
    }
    
	public void addCookie(Cookie cookie, boolean isSession) {

		boolean addSecureFlag = cookie.getSecure();
		boolean addHTTPOnlyFlag = false;

		if ( ! cookie.getSecure() && addSecureFlagRules != null ) {
			for(int i=0;i<addSecureFlagRules.size();i++) {
				AddSecureFlagRule asfr = addSecureFlagRules.get(i);
				if ( asfr.doesCookieMatch(cookie.getName())) {
					addSecureFlag = true;
				}
			}
		}

		if ( addHTTPOnlyFlagRules != null ) {
			for(int i=0;i<addHTTPOnlyFlagRules.size();i++) {
				AddHTTPOnlyFlagRule ashr = addHTTPOnlyFlagRules.get(i);
				if ( ashr.doesCookieMatch(cookie.getName())) {
					addHTTPOnlyFlag = true;
				}
			}
		}

		String cookieValue = createCookieHeader(cookie.getName(),cookie.getValue(),
												cookie.getMaxAge(),cookie.getDomain(),
												cookie.getPath(), addSecureFlag,
												addHTTPOnlyFlag, isSession);
		addHeader("Set-Cookie", cookieValue);


	}

	private String createCookieHeader(String name, String value, int maxAge, String domain, String path, boolean secure, boolean httpOnly, boolean isTemporary) {
        // create the special cookie header instead of creating a Java cookie
        // Set-Cookie:<name>=<value>[; <name>=<value>][; expires=<date>][;
        // domain=<domain_name>][; path=<some_path>][; secure][;HttpOnly
        String header = name + "=" + value;

        if ( ! isTemporary ) {
        	header += "; Max-Age=" + maxAge;
        }

        if (domain != null) {
            header += "; Domain=" + domain;
        }
        if (path != null) {
            header += "; Path=" + path;
        }

        if ( secure ) {
        	header += "; Secure";
        }

        if (httpOnly) {
        	header += "; HttpOnly";
        }

        return header;
    }

}
