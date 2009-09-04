package org.owasp.esapi.waf;

import java.net.URL;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

public class DetectOutboundTest extends WAFTestCase {
	
	public static TestSuite suite() {
		return new TestSuite(DetectOutboundTest.class);
	}
	
	public void testBadDetectOutbound() throws Exception {
	       
    	System.out.println("detectOutboundPolicy - Fires if response has \"2008\" in it" );
   	    
    	request = new MockHttpServletRequest( new URL( "http://www.example.com/here_is_the_2008" ) );
    	
    	// this setting of the body gets overridden in the MockFilterChain =(. For a hack we put it in
    	// the URI above, which gets reflected into the response body.
    	response.setBody( "Now is the time for all good men 2008 to come to the aid of their country" );
        
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/detect-outbound-policy.xml", request, response );
    	
    	assertTrue( response.getStatus() == HttpServletResponse.SC_MOVED_PERMANENTLY );
        
    }
	
	public void testGoodDetectOutbound() throws Exception {
	       
    	System.out.println("detectOutboundPolicy - should not fire even if response has \"2008\" in it because the content type is image/jpeg" );
   	    
    	request = new MockHttpServletRequest( new URL( "http://www.example.com/here_is_the_2008" ) );
    	response = new MockHttpServletResponse();
    	response.setContentType("image/jpeg");
    	response.setBody( "Now is the time for all good men 2008 to come to the aid of their country" );
        
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/detect-outbound-policy.xml", request, response );
    	
    	assertTrue( response.getStatus() == HttpServletResponse.SC_OK );
        
    }
}
