package org.owasp.esapi.waf;

import java.net.URL;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

public class RestrictMethodTest extends WAFTestCase {
	
	public static TestSuite suite() {
		return new TestSuite(RestrictMethodTest.class);
	}
	
	public void testGoodMethod() throws Exception {
		// test good method
	    url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest good method: " + url );
	    request = new MockHttpServletRequest( url );
	    request.setMethod( "TRACE" );
	    request.getSession(true); // so the app will pass the HttpOnly test...
	    
		response = new MockHttpServletResponse();
		createAndExecuteWAFResponseCodeTest(waf, request, response, HttpServletResponse.SC_OK );
	}
	
	public void testBadMethod() throws Exception {
		// test bad method
	    url = new URL( "http://www.example.com/index.jsp" );
		System.out.println( "\nTest bad method: " + url );
	    request = new MockHttpServletRequest( url );
	    request.setMethod( "JEFF" );
	    request.getSession(true); // so the app will pass the HttpOnly test...
	    
		response = new MockHttpServletResponse();
		createAndExecuteWAFResponseCodeTest( waf, request, response, HttpServletResponse.SC_MOVED_PERMANENTLY );
	}    
}
