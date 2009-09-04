/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.waf;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * This is the main TestSuite for all the WAF tests. Some of the WAF
 * tests utilize a large policy file containing a bunch of unrelated
 * rules, and some use very small policy files that only exercise
 * specific functionality. Some may use both. 
 * 
 * There is an unlimited combination of rules to be exercised together, 
 * so the small policy files test the strict functionality, while the
 * larger policy files (hopefully) give us assurance that the rules 
 * won't interfere with each other.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author Arshan Dabirsiaghi (arshan.dabirsiaghi@aspectsecurity.com)
 */

public class WAFFilterTest extends TestCase {
    
    /**
	 * Instantiates a new WAF test.
	 * 
	 * @param testName the test name
	 */
    public WAFFilterTest(String testName) {
        super(testName);
    }


    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {

    	TestSuite suite = new TestSuite(WAFFilterTest.class);

        suite.addTest(AddHeaderTest.suite());
        suite.addTest(DetectOutboundTest.suite());
        suite.addTest(EnforceAuthenticationTest.suite());
        suite.addTest(EnforceHTTPSTest.suite());
        suite.addTest(GoodRequestTest.suite());
        suite.addTest(HttpOnlyTest.suite());
        suite.addTest(MustMatchTest.suite());
        suite.addTest(DynamicInsertionTest.suite());
        suite.addTest(RestrictContentTypeTest.suite());
        suite.addTest(RestrictExtensionTest.suite());
        suite.addTest(RestrictMethodTest.suite());
        suite.addTest(RestrictUserAgentTest.suite());
        suite.addTest(VirtualPatchTest.suite());
        
        return suite;
    }
    
    public void testConfigurationCanBeRead() throws Exception {
    	
    	ESAPIWebApplicationFirewallFilter waf = new ESAPIWebApplicationFirewallFilter();
    	WAFTestUtility.setWAFPolicy(waf, "waf-policy.xml");

    }

}
