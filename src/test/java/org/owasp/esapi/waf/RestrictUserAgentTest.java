package org.owasp.esapi.waf;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

public class RestrictUserAgentTest extends WAFTestCase {
	public static TestSuite suite() {
		return new TestSuite(RestrictUserAgentTest.class);
	}
	
	public void testBadUserAgent() throws Exception {
		request.addHeader("User-Agent","GoogleBot");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-user-agent-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_MOVED_PERMANENTLY);
	}
	
	public void testGoodUserAgent() throws Exception {
		request.addHeader("User-Agent","MSIE NT Compatible");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-user-agent-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_OK);
	}
	
}
