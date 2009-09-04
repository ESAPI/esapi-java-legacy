package org.owasp.esapi.waf;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

public class WAFTestUtility {

    public static void setWAFPolicy( ESAPIWebApplicationFirewallFilter waf, String policyFile ) throws Exception {
        Map map = new HashMap();
    	map.put( "configuration", policyFile );
    	map.put( "log_settings", "log4j.xml");
    	FilterConfig mfc = new MockFilterConfig( map );
    	waf.init( mfc );
    }
    
    public static int checkWAFResult( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain chain ) throws Exception {

        //request.dump();
    	waf.doFilter(request, response, chain);
        //response.dump();
        
        return response.getStatus();
       
    }  

    public static int createAndExecuteWAFTransaction ( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response ) throws Exception {

		MockFilterChain chain = new MockFilterChain();
		
		return WAFTestUtility.checkWAFResult(waf, request, response, chain);
		
	}

    public static int createAndExecuteWAFTransaction ( ESAPIWebApplicationFirewallFilter waf, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain filterChain ) throws Exception {

		MockFilterChain chain = new MockFilterChain();
		
		return WAFTestUtility.checkWAFResult(waf, request, response, filterChain);
		
	}
    
    public static int createAndExecuteWAFTransaction ( String policy, MockHttpServletRequest request, MockHttpServletResponse response ) throws Exception {

    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	InputStream is = ESAPI.securityConfiguration().getResourceStream( policy );
    	waf.setConfiguration(is);

		return createAndExecuteWAFTransaction(waf, request, response );
		
	}
    
    public static int createAndExecuteWAFTransaction ( String policy, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain filterChain ) throws Exception {

    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	InputStream is = ESAPI.securityConfiguration().getResourceStream( policy );
    	waf.setConfiguration(is);

		return createAndExecuteWAFTransaction(waf, request, response, filterChain );
		
	}
}
