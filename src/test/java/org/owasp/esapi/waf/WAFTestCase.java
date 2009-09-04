package org.owasp.esapi.waf;

import java.net.URL;

import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.reference.DefaultEncoder;

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
			String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
			Authenticator instance = ESAPI.authenticator();
			String password = instance.generateStrongPassword();
			instance.setCurrentUser(user);
			user = instance.createUser(accountName, password, password);
			user.enable();
		}
		
		request = new MockHttpServletRequest( new URL( "http://www.example.com/index" ) );
        response = new MockHttpServletResponse();
        waf = new ESAPIWebApplicationFirewallFilter();
        
        WAFTestUtility.setWAFPolicy(waf, "waf-policy.xml");
	}
    
	public void createAndExecuteWAFResponseCodeTest( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, int expectedResult ) throws Exception {
    	assertEquals ( expectedResult, WAFTestUtility.createAndExecuteWAFTransaction( waf, request, response) );	
	}
    
    public void createAndExecuteWAFResponseCodeTest( String policy, MockHttpServletRequest request, MockHttpServletResponse response, int expectedResult ) throws Exception {
    	assertEquals ( expectedResult, WAFTestUtility.createAndExecuteWAFTransaction( policy, request, response) );	
	}
}
