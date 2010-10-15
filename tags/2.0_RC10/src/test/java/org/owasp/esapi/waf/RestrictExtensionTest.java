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

public class RestrictExtensionTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(RestrictExtensionTest.class);
	}
	
	public void testGoodExtension() throws Exception {
        
    	System.out.println("restrictExtensionPolicy - approve this URL (doesn't end in .log or anything else evil)" );

        request = new MockHttpServletRequest( new URL( "http://www.example.com/logfiles/12192009.jpg" ) );
        request.getSession(true); // pass HttpOnly test...
    	response = new MockHttpServletResponse();
        
        WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-extension-policy.xml", request, response );
    	
    	assertTrue( response.getStatus() != HttpServletResponse.SC_MOVED_PERMANENTLY );
    }

	public void testBadExtension() throws Exception {
        
    	System.out.println("restrictExtensionPolicy - reject any URL ending in .log" );

        MockHttpServletRequest request = new MockHttpServletRequest( new URL( "http://www.example.com/logfiles/12192009.log" ) );
    	MockHttpServletResponse response = new MockHttpServletResponse();
        
        WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-extension-policy.xml", request, response );
    	
    	assertTrue( response.getStatus() == HttpServletResponse.SC_MOVED_PERMANENTLY );
    }
}
