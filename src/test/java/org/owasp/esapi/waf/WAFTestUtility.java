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
 * 
 * @created 2009
 */
package org.owasp.esapi.waf;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterConfig;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.http.MockFilterChain;
import org.owasp.esapi.http.MockFilterConfig;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * This class holds a number of static utilities to make writing WAF test cases easy. Definitely not useful
 * for anything other than testing.
 */
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


    	return WAFTestUtility.checkWAFResult(waf, request, response, filterChain);
		
	}
    
    public static int createAndExecuteWAFTransaction ( String policy, MockHttpServletRequest request, MockHttpServletResponse response ) throws Exception {

    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	File f = ESAPI.securityConfiguration().getResourceFile(policy);
    	waf.setConfiguration(f.getAbsolutePath(),"");

		return createAndExecuteWAFTransaction(waf, request, response );
		
	}
    
    public static int createAndExecuteWAFTransaction ( String policy, MockHttpServletRequest request, MockHttpServletResponse response, MockFilterChain filterChain ) throws Exception {

    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	File f = ESAPI.securityConfiguration().getResourceFile(policy);        
    	waf.setConfiguration(f.getAbsolutePath(),"");

		return createAndExecuteWAFTransaction(waf, request, response, filterChain );
		
	}
}
