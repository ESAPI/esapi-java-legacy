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

import javax.servlet.http.HttpServletResponse;

import junit.framework.TestSuite;

public class RestrictUserAgentTest extends WAFTestCase {
	
	public static TestSuite suite() {
		return new TestSuite(RestrictUserAgentTest.class);
	}
	
	public void testBadUserAgent() throws Exception {
		
		request.addHeader("User-Agent","GoogleBot");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-user-agent-policy.xml", request, response );
		
		assert(response.getStatus() == 403);
	}
	
	public void testGoodUserAgent() throws Exception {
		
		request.addHeader("User-Agent","MSIE NT Compatible");
		
		WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/restrict-user-agent-policy.xml", request, response );
    	
		assert(response.getStatus() == HttpServletResponse.SC_OK);
	}
	
}
