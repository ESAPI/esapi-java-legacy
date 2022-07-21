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
package org.owasp.esapi.waf;

import java.net.URL;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

public class MustMatchTest extends WAFTestCase {

    public static TestSuite suite() {
        return new TestSuite(MustMatchTest.class);
    }

    public void testUnauthorizedRequest () throws Exception {
        // Test bad request (no x-roles header)
        url = new URL( "https://www.example.com/admin/config" );
        System.out.println( "\nTest bad request (request has no x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.setRemoteAddr("192.168.1.5"); // necessary to pass IPRule
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        response = new MockHttpServletResponse();
        createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_MOVED_PERMANENTLY );
    }

    public void testAuthorizedRequest() throws Exception {
        // Test good request (request has x-roles header)
        url = new URL( "https://www.example.com/admin/config" );
        System.out.println( "\nTest good request (request has x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.addHeader("x-roles", "admin" );
        request.setRemoteAddr("192.168.1.100");
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        response = new MockHttpServletResponse();
        createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_OK );
    }
}
