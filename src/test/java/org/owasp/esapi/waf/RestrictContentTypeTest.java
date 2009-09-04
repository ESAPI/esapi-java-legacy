package org.owasp.esapi.waf;

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

public class RestrictContentTypeTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(RestrictContentTypeTest.class);
	}

	public void testNoContentType() throws Exception {

		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-content-type-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_OK);
	}
	
	public void testGoodContentType() throws Exception {
		request.addHeader("Content-Type","text/html");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-content-type-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_OK);
	}
	
	public void testBadContentType() throws Exception {
		request.addHeader("Content-Type","multipart/form-upload");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-content-type-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_MOVED_PERMANENTLY);
	}
	
}
