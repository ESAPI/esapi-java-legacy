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

import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

import junit.framework.TestSuite;

public class VirtualPatchTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(VirtualPatchTest.class);
	}
	
	public void testNonAttacktAfterVirtualPatch() throws Exception {
		// should pass
        url = new URL( "https://www.example.com/virtualpatch.jsp" );
		System.out.println( "Testing non-attack after virtual patch on URL: " + url );
        request = new MockHttpServletRequest( url );
        request.getSession(true);
        request.setScheme("https");
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        request.addParameter("bar", "09124asd135r123irh2938rh9c82hr3hareohvw"); // alphanums are allowed
        request.addParameter("foo", "<script>' oR 1=1-- bad.attax.google.com jar:"); // this parameter should not be touched by the patch
    	response = new MockHttpServletResponse();
    	createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_OK );
	}
	
	public void testAttackAfterVirtualPatch() throws Exception {
		// should fail
        url = new URL( "https://www.example.com/virtualpatch.jsp" );
		System.out.println( "Testing attack after virtual patch on URL: " + url );
        request = new MockHttpServletRequest( url );
        request.getSession(true);
        request.setScheme("https");
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        request.addParameter("bar", "09124asd135r123ir>h2938rh9c82hr3hareohvw"); // non-alphanums are not allowed (there is 1 in the middle)
        request.addParameter("foo", "SADFSDfSDFSDF123123123"); // this parameter should not be touched by the patch
    	response = new MockHttpServletResponse();
    	createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_MOVED_PERMANENTLY );
	}
}
