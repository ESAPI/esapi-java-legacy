package org.owasp.esapi.waf;

import java.net.URL;

import org.owasp.esapi.http.MockHttpServletRequest;

import junit.framework.TestSuite;

public class AddHeaderTest extends WAFTestCase {
	
	public static TestSuite suite() {
		return new TestSuite(AddHeaderTest.class);
	}
	
    /*
     * Test whether or not the WAF correctly adds the header to the response when it should and
     * when it shouldn't, based on paths specified in the WAF rules.
     */
    public void testShouldAddHeader() throws Exception {
        
    	System.out.println("addHeaderPolicy - Response should have FOO=BAR header added" );

    	request = new MockHttpServletRequest( new URL( "http://www.example.com/addheader" ) );
    	
    	WAFTestUtility.createAndExecuteWAFTransaction("waf-policies/add-header-policy.xml", request, response );
    	
        String foo = response.getHeader( "FOO" );
        assertTrue( foo != null && foo.equals( "BAR" ) );
        
    }
    
    public void testShouldNotAddHeader() throws Exception {
    	System.out.println("addHeaderPolicy - Response should have FOO=BAR header added" );

    	request = new MockHttpServletRequest( new URL( "http://www.example.com/marketing/foo" ) );
    	
    	WAFTestUtility.createAndExecuteWAFTransaction("waf-policies/add-header-policy.xml", request, response );
    	
        String foo = response.getHeader( "FOO" );
        assertTrue( foo == null );
        
    }

}
