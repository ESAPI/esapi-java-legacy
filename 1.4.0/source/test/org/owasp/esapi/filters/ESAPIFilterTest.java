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
package org.owasp.esapi.filters;

import javax.servlet.http.HttpSession;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.http.TestFilterChain;
import org.owasp.esapi.http.TestHttpServletRequest;
import org.owasp.esapi.http.TestHttpServletResponse;
import org.owasp.esapi.reference.DefaultEncoder;

/**
 * The Class AccessReferenceMapTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class ESAPIFilterTest extends TestCase {
    
    /**
	 * Instantiates a new access reference map test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public ESAPIFilterTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     */
    protected void setUp() throws Exception {
    	// none
    }

    /**
     * {@inheritDoc}
     */
    protected void tearDown() throws Exception {
    	// none
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(ESAPIFilterTest.class);
        return suite;
    }

    
    /**
	 * Test of update method, of class org.owasp.esapi.AccessReferenceMap.
	 * 
	 * @throws AuthenticationException
	 *             the authentication exception
	 */
    public void testFilter() throws Exception {
        System.out.println("ESAPIFilter");
        ESAPIFilter filter = new ESAPIFilter();
        System.out.println(">>>" + ESAPI.securityConfiguration().getResourceDirectory() );
        
        // setup the user in session
		String accountName = ESAPI.randomizer().getRandomString(8, DefaultEncoder.CHAR_ALPHANUMERICS);
		Authenticator instance = ESAPI.authenticator();
		String password = instance.generateStrongPassword();
		User user = instance.createUser(accountName, password, password);
		instance.setCurrentUser(user);
		user.enable();
   	    TestHttpServletRequest request = new TestHttpServletRequest();
		TestHttpServletResponse response = new TestHttpServletResponse();
		TestFilterChain chain = new TestFilterChain();
        HttpSession session = request.getSession();
        session.setAttribute("ESAPIUserSessionKey", user);
		
        // setup the URI
        request.setRequestURI("/test/all");

        // basic test
        filter.doFilter(request, response, chain);

        // header injection test
        request.addParameter("test", "test%0d%0a%0d%0awordpad" );
        filter.doFilter(request, response, chain);
    
        // access control test
        request.setRequestURI( "/ridiculous" );
        filter.doFilter(request, response, chain);
    
        // authentication test
        // TODO: why isn't this invoking the authentication code
        session.removeAttribute("ESAPIUserSessionKey");
        filter.doFilter(request, response, chain);
    }
    
}
