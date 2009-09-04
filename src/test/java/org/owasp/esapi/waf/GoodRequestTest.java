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
