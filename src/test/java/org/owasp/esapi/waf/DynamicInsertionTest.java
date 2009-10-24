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

import java.io.IOException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockHttpServletRequest;

import junit.framework.TestSuite;

public class DynamicInsertionTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(DynamicInsertionTest.class);
	}
	
	public void testShouldReplaceContent() throws Exception {
		
    	System.out.println("dynamicInsertionPolicy - replaces </body> with 'this is a test'" );
   	    
    	request = new MockHttpServletRequest( new URL( "https://www.example.com/here+</body>+there+everywhere" ) );
        request.setScheme("https");
        request.getSession(true).setAttribute("ESAPIUserSessionKey", user);
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/dynamic-insertion-policy.xml", request, response );
    	
    	assertTrue ( response.getStatus() == HttpServletResponse.SC_OK );
    	assertTrue ( response.getBody().indexOf("test") > -1 );
    	System.out.println( response.getBody() );
   	
	}
	
	public void testShouldNotReplaceContent() throws Exception {
		
		System.out.println("dynamicInsertionPolicy - should not replace '< /body>' or </body > or </bo dy> with anything" );
   	    
    	request = new MockHttpServletRequest( new URL( "https://www.example.com/here+<+/body></bo+dy>+</body+>+there+everywhere" ) );
    	request.setScheme("https");
    	request.getSession(true).setAttribute("ESAPIUserSessionKey", user);
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/dynamic-insertion-policy.xml", request, response );
    	
    	assertTrue ( response.getStatus() == HttpServletResponse.SC_OK );
    	assertTrue ( response.getBody().indexOf("test") == -1 );
    	System.out.println( response.getBody() );
   		
    	
	}
	
}
