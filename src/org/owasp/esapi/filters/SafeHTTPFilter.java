/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.ESAPI;


/**
 * This filter wraps the incoming request and outgoing response and overrides
 * many methods with safer versions. Many of the safer versions simply validate
 * parts of the request or response for unwanted characters before allowing the
 * call to complete. Some examples of attacks that use these
 * vectors include request splitting, response splitting, and file download
 * injection. Attackers use techniques like CRLF injection and null byte injection
 * to confuse the parsing of requests and responses.
 */
public class SafeHTTPFilter implements Filter {

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest hrequest = (HttpServletRequest)request;
        HttpServletResponse hresponse = (HttpServletResponse)response;
        ESAPI.httpUtilities().setCurrentHTTP(hrequest, hresponse);
        chain.doFilter(new SafeRequest(hrequest), new SafeResponse(hresponse));
    }

	public void destroy() {
		// no special action
	}

	public void init(FilterConfig filterConfig) throws ServletException {
		// no special action
	}
	
}
