/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.io.IOException;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.AuthenticationException;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationException;
import org.owasp.esapi.http.TestHttpServletRequest;
import org.owasp.esapi.http.TestHttpServletResponse;

/**
 * The Class LoggerTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class LoggerTest extends TestCase {
    
    /**
	 * Instantiates a new logger test.
	 * 
	 * @param testName
	 *            the test name
	 */
    public LoggerTest(String testName) {
        super(testName);
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
    	// none
    }

    /* (non-Javadoc)
     * @see junit.framework.TestCase#tearDown()
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
        TestSuite suite = new TestSuite(LoggerTest.class);
        
        return suite;
    }

    /**
     * Test of logHTTPRequest method, of class org.owasp.esapi.Logger.
     * 
     * @throws ValidationException
     *             the validation exception
     * @throws IOException
     *             Signals that an I/O exception has occurred.
     * @throws AuthenticationException
     *             the authentication exception
     */
    public void testLogHTTPRequest() throws ValidationException, IOException, AuthenticationException {
        System.out.println("logHTTPRequest");
        String[] ignore = {"password","ssn","ccn"};
        TestHttpServletRequest request = new TestHttpServletRequest();
        TestHttpServletResponse response = new TestHttpServletResponse();
        ESAPI.httpUtilities().setCurrentHTTP(request, response);
        // FIXME: AAA modify to return the actual string logged (so we can test)
        JavaLogger logger = new JavaLogger("logger", "logger");
        ESAPI.httpUtilities().logHTTPRequest( logger, Arrays.asList(ignore) );
        request.addParameter("one","one");
        request.addParameter("two","two1");
        request.addParameter("two","two2");
        request.addParameter("password","jwilliams");
        ESAPI.httpUtilities().logHTTPRequest( logger, Arrays.asList(ignore) );
    }    
    
    /**
	 * Test of logSuccess method, of class org.owasp.esapi.Logger.
	 */
    public void testInfo() {
        System.out.println("info");
        new JavaLogger( "app", "mod" ).info(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).info(JavaLogger.SECURITY, "test message", null );
        new JavaLogger( "app", "mod" ).info(JavaLogger.SECURITY, "%3escript%3f test message", null );
        new JavaLogger( "app", "mod" ).info(JavaLogger.SECURITY, "<script> test message", null );
    }


    /**
	 * Test of logTrace method, of class org.owasp.esapi.Logger.
	 */
    public void testTrace() {
        System.out.println("trace");
        new JavaLogger( "app", "mod" ).trace(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).trace(JavaLogger.SECURITY, "test message", null );
    }

    /**
	 * Test of logDebug method, of class org.owasp.esapi.Logger.
	 */
    public void testDebug() {
        System.out.println("debug");
        new JavaLogger( "app", "mod" ).debug(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).debug(JavaLogger.SECURITY, "test message", null );
    }

    /**
	 * Test of logError method, of class org.owasp.esapi.Logger.
	 */
    public void testError() {
        System.out.println("error");
        new JavaLogger( "app", "mod" ).error(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).error(JavaLogger.SECURITY, "test message", null );
    }

    /**
	 * Test of logWarning method, of class org.owasp.esapi.Logger.
	 */
    public void testWarning() {
        System.out.println("warning");
        new JavaLogger( "app", "mod" ).warning(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).warning(JavaLogger.SECURITY, "test message", null );
    }

    /**
	 * Test of logCritical method, of class org.owasp.esapi.Logger.
	 */
    public void testFatal() {
        System.out.println("fatal");
        new JavaLogger( "app", "mod" ).fatal(JavaLogger.SECURITY, "test message" );
        new JavaLogger( "app", "mod" ).fatal(JavaLogger.SECURITY, "test message", null );
    }
    
}
