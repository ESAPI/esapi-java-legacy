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
package org.owasp.esapi.waf;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletResponse;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.reference.DefaultEncoder;

/**
 * The Class AccessReferenceMapTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class WAFFilterTest extends TestCase {
    
    /**
	 * Instantiates a new access reference map test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public WAFFilterTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(WAFFilterTest.class);
        return suite;
    }

    
    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 * 
     *
     * @throws Exception
     */
    public void testFilter() throws Exception {
        System.out.println("ESAPIWAFFilter");

        Map map = new HashMap();
    	map.put( "configuration", "waf-policy.xml");
    	map.put( "log_settings", "log4j.xml");
    	FilterConfig mfc = new MockFilterConfig( map );
    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();        
    	waf.init( mfc );
   	    MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
		MockHttpServletResponse response = new MockHttpServletResponse();
		
		// the mock filter chain writes the requested URI to the response body
		MockFilterChain chain = new MockFilterChain();

        // setup the user in session
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		instance.setCurrentUser(user);
		user.enable();

        // should pass
        response.reset();
        URL url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest good URL: " + url );
        request = new MockHttpServletRequest( url );
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );
        
        // test good scheme
        response.reset();
        url = new URL( "https://www.example.com/" );
		System.out.println( "\nTest good scheme: " + url );
        request = new MockHttpServletRequest( url );
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );
        
        // test bad scheme
        response.reset();
        url = new URL( "http://www.example.com/images/test.jpg" );
		System.out.println( "\nTest bad scheme (no ssl): " + url );
        request = new MockHttpServletRequest( url );
        doFilter( waf, request, response, chain, HttpServletResponse.SC_MOVED_PERMANENTLY );
        
        // test good method
        response.reset();
        url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest good method: " + url );
        request = new MockHttpServletRequest( url );
        request.setMethod( "TRACE" );
        doFilter(waf, request, response, chain, HttpServletResponse.SC_OK );

        // test bad method
        response.reset();
        url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest bad method: " + url );
        request = new MockHttpServletRequest( url );
        request.setMethod( "JEFF" );
        doFilter( waf, request, response, chain, HttpServletResponse.SC_MOVED_PERMANENTLY );

        // authentication test - NOT DONE YET
        response.reset();
        url = new URL( "https://www.example.com/authenticated" );
		System.out.println( "\nTest good request (user in session): " + url );
        request = new MockHttpServletRequest( url );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );

        // authentication test
        response.reset();
        url = new URL( "http://www.example.com/authenticated" );
		System.out.println( "\nTest bad request (no user in session): " + url );
        request = new MockHttpServletRequest( url );
        doFilter( waf, request, response, chain, HttpServletResponse.SC_MOVED_PERMANENTLY );
        
        // Test protected URL
        response.reset();
        url = new URL( "https://www.example.com/admin/config" );
		System.out.println( "\nTest good request (request has x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.addHeader("x-roles", "admin" );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );

        // Test protected URL
        response.reset();
        url = new URL( "https://www.example.com/admin/config" );
		System.out.println( "\nTest bad request (request has no x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        doFilter( waf, request, response, chain, HttpServletResponse.SC_MOVED_PERMANENTLY );

        // Test special rule
        response.reset();
        url = new URL( "https://www.example.com/foo.jsp" );
		System.out.println( "\nTest bad request (matches special rule): " + url );
        request = new MockHttpServletRequest( url );
        request.addParameter( "NameWithNY", "ValueWithNY" );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
        doFilter( waf, request, response, chain, HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
    }
    
    private void doFilter( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain chain, int expectedResult ) {
        try {
        	waf.doFilter(request, response, chain);
        } catch( Exception e ) {
        	e.printStackTrace();
        	fail();
        }
        System.out.println(">>>" + response.getStatus() + " " + response.getBody().trim() );
        // assertEquals( expectedResult, response.getStatus() );
    }
}
