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

import java.io.InputStream;
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
        // setup the user in session
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		instance.setCurrentUser(user);
		user.enable();
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


    public static void setWAFPolicy( ESAPIWebApplicationFirewallFilter waf, String policyFile ) throws Exception {
        Map map = new HashMap();
    	map.put( "configuration", policyFile );
    	map.put( "log_settings", "log4j.xml");
    	FilterConfig mfc = new MockFilterConfig( map );
    	waf.init( mfc );
    }
    
    /**
     * @throws Exception
     */
    public void testFilter() throws Exception {
        System.out.println("ESAPIWAFFilter");
    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();        
    	setWAFPolicy( waf, "waf-policy.xml" );
		
		// the mock filter chain writes the requested URI to the response body
		MockFilterChain chain = new MockFilterChain();
   	    MockHttpServletRequest request = new MockHttpServletRequest();
    	MockHttpServletResponse response = new MockHttpServletResponse();

        // setup the user in session
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		instance.setCurrentUser(user);
		user.enable();

        // should pass
        URL url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest good URL: " + url );
        request = new MockHttpServletRequest( url );
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );
        
        // test good scheme
        url = new URL( "https://www.example.com/" );
		System.out.println( "\nTest good scheme (https): " + url );
        request = new MockHttpServletRequest( url );
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );
                
        // test bad scheme
        url = new URL( "http://www.example.com/images/test.jpg" );
		System.out.println( "\nTest bad scheme (no ssl): " + url );
        request = new MockHttpServletRequest( url );
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_FORBIDDEN );
        
        // test good method
        url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest good method: " + url );
        request = new MockHttpServletRequest( url );
        request.setMethod( "TRACE" );
    	response = new MockHttpServletResponse();
        doFilter(waf, request, response, chain, HttpServletResponse.SC_OK );

        // test bad method
        url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest bad method: " + url );
        request = new MockHttpServletRequest( url );
        request.setMethod( "JEFF" );
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_FORBIDDEN );

        // authentication test
        url = new URL( "https://www.example.com/authenticated" );
		System.out.println( "\nTest good request (user in session): " + url );
        request = new MockHttpServletRequest( url );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );

        // authentication test
        url = new URL( "http://www.example.com/authenticated" );
		System.out.println( "\nTest bad request (no user in session): " + url );
        request = new MockHttpServletRequest( url );
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_FORBIDDEN );
        
        // Test good request (request has x-roles header)
        url = new URL( "https://www.example.com/admin/config" );
		System.out.println( "\nTest good request (request has x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.addHeader("x-roles", "admin" );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_OK );

        // Test bad request (no x-roles header)
        url = new URL( "https://www.example.com/admin/config" );
		System.out.println( "\nTest bad request (request has no x-roles header): " + url );
        request = new MockHttpServletRequest( url );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_MOVED_PERMANENTLY );

        // Test special rule
        url = new URL( "https://www.example.com/zaz.jsp" );
		System.out.println( "\nTest bad request (matches special rule): " + url );
        request = new MockHttpServletRequest( url );
        request.addParameter( "NameWithNY", "ValueWithNY" );
        request.getSession().setAttribute("ESAPIUserSessionKey", user);
    	response = new MockHttpServletResponse();
        doFilter( waf, request, response, chain, HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
    }
    
    public void testAddHeaderPolicy() throws Exception {
        System.out.println("addHeaderPolicy - Response should have FOO=BAR header added" );
   	    MockHttpServletRequest request = new MockHttpServletRequest( new URL( "http://www.example.com/index" ) );
    	MockHttpServletResponse response = new MockHttpServletResponse();
        executeTest( "waf-policies/add-header-policy.xml", request, response, true ); 
        String foo = response.getHeader( "FOO" );
        assertTrue( foo != null && foo.equals( "BAR" ) );
    }

    public void testAddHttpOnlyPolicy() throws Exception {
        System.out.println("addHttpOnlyPolicy - Response should have httpOnly set on any cookie added to response" );
   	    MockHttpServletRequest request = new MockHttpServletRequest( new URL( "http://www.example.com/index" ) );
    	MockHttpServletResponse response = new MockHttpServletResponse();
        executeTest( "waf-policies/add-httponly-policy.xml", request, response, true );
        String header = response.getHeader("Set-Cookie" );
        assertTrue( header == header );
    }

    public void testDetectOutboundPolicy() throws Exception {
        System.out.println("detectOutboundPolicy - Fires if response has \"2008\" in it" );
   	    MockHttpServletRequest request = new MockHttpServletRequest( new URL( "http://www.example.com/index" ) );
    	MockHttpServletResponse response = new MockHttpServletResponse();
    	response.setBody( "Now is the time for all good men 2008 to come to the aid of their country" );
        executeTest( "waf-policies/detect-outbound-policy.xml", request, response, true );
        assertTrue( true );
    }


    public void testRestrictExtensionPolicy() throws Exception {
        System.out.println("restrictExtensionPolicy - reject any URL ending in .log" );
   	    MockHttpServletRequest request = new MockHttpServletRequest( new URL( "http://www.example.com/logfiles/12192009.log" ) );
    	MockHttpServletResponse response = new MockHttpServletResponse();
        executeTest( "waf-policies/restrict-extension-policy.xml", request, response, false );
        assertTrue( true );
    }

    
    
    
    
    public void executeTest( String policy, MockHttpServletRequest request, MockHttpServletResponse response, boolean ok ) throws Exception {
    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	InputStream is = ESAPI.securityConfiguration().getResourceStream( policy );
    	waf.setConfiguration(is);
    	System.out.println( waf.getConfiguration() );
		MockFilterChain chain = new MockFilterChain();
        doFilter( waf, request, response, chain, ok ? HttpServletResponse.SC_OK : HttpServletResponse.SC_FORBIDDEN );
	}
    
    private void doFilter( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain chain, int expectedResult ) {
    	try {
            request.dump();
        	waf.doFilter(request, response, chain);
            response.dump();
        } catch( Exception e ) {
        	e.printStackTrace();
        	fail();
        }
        assertEquals( expectedResult, response.getStatus() );
    }    
    
}
