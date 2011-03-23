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

public class GoodRequestTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(GoodRequestTest.class);
	}
	
	public void testGoodRequest() throws Exception {
		// should pass
        url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "Test good URL: " + url );
        request = new MockHttpServletRequest( url );
        request.getSession(true);
    	response = new MockHttpServletResponse();
    	createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_OK );
	}
	
}
