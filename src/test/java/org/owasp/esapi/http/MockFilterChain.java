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
package org.owasp.esapi.http;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 *
 * @author jwilliams
 */
public class MockFilterChain implements FilterChain {
    /**
     *
     * @param request
     * @param response
     * @throws java.io.IOException
     * @throws jakarta.servlet.ServletException
     */
    public void doFilter( ServletRequest request, ServletResponse response ) throws IOException, ServletException {
        System.out.println( "CHAIN received " + request.getClass().getName() + " and is issuing " + response.getClass().getName() );
           response.getOutputStream().println( "   This is the body of a response for " +  ((HttpServletRequest)request).getRequestURI() );
               ((HttpServletResponse)response).addCookie( new Cookie( "name", "value" ) );
    }

}
