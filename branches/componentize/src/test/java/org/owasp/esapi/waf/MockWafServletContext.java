package org.owasp.esapi.waf;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.http.MockServletContext;

public class MockWafServletContext extends MockServletContext {

	public String getRealPath(String s) {
		
		return ESAPI.securityConfiguration().getResourceFile( "" ).getAbsolutePath() + "/" + s;
		
	}
	
}
