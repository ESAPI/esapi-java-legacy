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
