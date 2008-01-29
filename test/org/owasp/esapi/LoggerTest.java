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
package org.owasp.esapi;

import java.io.IOException;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.TestHttpServletRequest;

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
        // FIXME: AAA modify to return the actual string logged (so we can test)
        Logger.getLogger("logger", "logger").logHTTPRequest(Logger.SECURITY, request, Arrays.asList(ignore) );
        request.addParameter("one","one");
        request.addParameter("two","two1");
        request.addParameter("two","two2");
        request.addParameter("password","jwilliams");
        Logger.getLogger("logger", "logger").logHTTPRequest(Logger.SECURITY, request, Arrays.asList(ignore) );
    }    
    
    /**
	 * Test of logSuccess method, of class org.owasp.esapi.Logger.
	 */
    public void testLogSuccess() {
        System.out.println("logSuccess");
        Logger.getLogger( "app", "mod" ).logSuccess(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logSuccess(Logger.SECURITY, "test message", null );
        Logger.getLogger( "app", "mod" ).logSuccess(Logger.SECURITY, "%3escript%3f test message", null );
        Logger.getLogger( "app", "mod" ).logSuccess(Logger.SECURITY, "<script> test message", null );
    }


    /**
	 * Test of logTrace method, of class org.owasp.esapi.Logger.
	 */
    public void testLogTrace() {
        System.out.println("logTrace");
        Logger.getLogger( "app", "mod" ).logTrace(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logTrace(Logger.SECURITY, "test message", null );
    }

    /**
	 * Test of logDebug method, of class org.owasp.esapi.Logger.
	 */
    public void testLogDebug() {
        System.out.println("logDebug");
        Logger.getLogger( "app", "mod" ).logDebug(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logDebug(Logger.SECURITY, "test message", null );
    }

    /**
	 * Test of logError method, of class org.owasp.esapi.Logger.
	 */
    public void testLogError() {
        System.out.println("logError");
        Logger.getLogger( "app", "mod" ).logError(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logError(Logger.SECURITY, "test message", null );
    }

    /**
	 * Test of logWarning method, of class org.owasp.esapi.Logger.
	 */
    public void testLogWarning() {
        System.out.println("logWarning");
        Logger.getLogger( "app", "mod" ).logWarning(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logWarning(Logger.SECURITY, "test message", null );
    }

    /**
	 * Test of logCritical method, of class org.owasp.esapi.Logger.
	 */
    public void testLogCritical() {
        System.out.println("logCritical");
        Logger.getLogger( "app", "mod" ).logCritical(Logger.SECURITY, "test message" );
        Logger.getLogger( "app", "mod" ).logCritical(Logger.SECURITY, "test message", null );
    }
    
}
