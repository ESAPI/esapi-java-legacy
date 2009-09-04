package org.owasp.esapi.waf;

import java.io.IOException;
import java.net.URL;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockHttpServletRequest;

import junit.framework.TestSuite;

public class DynamicInsertionTest extends WAFTestCase {

	public static TestSuite suite() {
		return new TestSuite(DynamicInsertionTest.class);
	}
	
	public void testShouldReplaceContent() throws Exception {
		
    	System.out.println("dynamicInsertionPolicy - replaces </body> with 'this is a test'" );
   	    
    	request = new MockHttpServletRequest( new URL( "https://www.example.com/here+</body>+there+everywhere" ) );
        request.setScheme("https");
        request.getSession(true).setAttribute("ESAPIUserSessionKey", user);
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/dynamic-insertion-policy.xml", request, response );
    	
    	assertTrue ( response.getStatus() == HttpServletResponse.SC_OK );
    	assertTrue ( response.getBody().indexOf("test") > -1 );
    	System.out.println( response.getBody() );
   	
	}
	
	public void testShouldNotReplaceContent() throws Exception {
		
		System.out.println("dynamicInsertionPolicy - should not replace '< /body>' or </body > or </bo dy> with anything" );
   	    
    	request = new MockHttpServletRequest( new URL( "https://www.example.com/here+<+/body></bo+dy>+</body+>+there+everywhere" ) );
    	request.setScheme("https");
    	request.getSession(true).setAttribute("ESAPIUserSessionKey", user);
    	WAFTestUtility.createAndExecuteWAFTransaction( "waf-policies/dynamic-insertion-policy.xml", request, response );
    	
    	assertTrue ( response.getStatus() == HttpServletResponse.SC_OK );
    	assertTrue ( response.getBody().indexOf("test") == -1 );
    	System.out.println( response.getBody() );
   		
    	
	}
	
}
