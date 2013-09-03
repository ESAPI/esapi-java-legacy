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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf;

import java.net.URL;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.User;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

import junit.framework.TestCase;

public abstract class WAFTestCase extends TestCase {

	protected MockHttpServletRequest request;
	protected MockHttpServletResponse response;
	protected URL url;
	protected ESAPIWebApplicationFirewallFilter waf;
	
	protected static User user = null;
	
	public void setUp() throws Exception {
	    // setup the user in session
		
		if ( user == null ) {
			String accountName = ESAPI.randomizer().getRandomString(8, EncoderConstants.CHAR_ALPHANUMERICS);
			Authenticator instance = ESAPI.authenticator();
			String password = instance.generateStrongPassword();
			instance.setCurrentUser(user);
			user = instance.createUser(accountName, password, password);
			user.enable();
		}
		
		request = new MockHttpServletRequest( new URL( "http://www.example.com/index" ) );
        response = new MockHttpServletResponse();
        waf = new ESAPIWebApplicationFirewallFilter();
        
        WAFTestUtility.setWAFPolicy(waf, "/waf-policy.xml");
	}
    
	public void createAndExecuteWAFResponseCodeTest( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, int expectedResult ) throws Exception {
    	assertEquals ( expectedResult, WAFTestUtility.createAndExecuteWAFTransaction( waf, request, response) );	
	}
    
    public void createAndExecuteWAFResponseCodeTest( String policy, MockHttpServletRequest request, MockHttpServletResponse response, int expectedResult ) throws Exception {
    	assertEquals ( expectedResult, WAFTestUtility.createAndExecuteWAFTransaction( policy, request, response) );	
	}
}
