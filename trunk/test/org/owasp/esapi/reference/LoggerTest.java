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
package org.owasp.esapi.reference;

import java.io.IOException;
import java.util.Arrays;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.ValidationException;
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
        Logger logger = ESAPI.getLogger("logger");
        ESAPI.httpUtilities().logHTTPRequest( request, logger, Arrays.asList(ignore) );
        request.addParameter("one","one");
        request.addParameter("two","two1");
        request.addParameter("two","two2");
        request.addParameter("password","jwilliams");
        ESAPI.httpUtilities().logHTTPRequest( request, logger, Arrays.asList(ignore) );
    }    
    
    
    /**
     * Test of setLevel method of the inner class org.owasp.esapi.reference.JavaLogger that is defined in 
     * org.owasp.esapi.reference.JavaLogFactory.
     */
    public void testSetLevel() {
        System.out.println("setLevel");
        Logger myLogger = ESAPI.getLogger( "mod" );
        
        myLogger.setLevel( Logger.ALL );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertTrue(myLogger.isWarningEnabled());
       	assertTrue(myLogger.isInfoEnabled());
       	assertTrue(myLogger.isDebugEnabled());
       	assertTrue(myLogger.isTraceEnabled());

       	myLogger.setLevel( Logger.TRACE );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertTrue(myLogger.isWarningEnabled());
       	assertTrue(myLogger.isInfoEnabled());
       	assertTrue(myLogger.isDebugEnabled());
       	assertTrue(myLogger.isTraceEnabled());

       	myLogger.setLevel( Logger.DEBUG );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertTrue(myLogger.isWarningEnabled());
       	assertTrue(myLogger.isInfoEnabled());
       	assertTrue(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	myLogger.setLevel( Logger.INFO );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertTrue(myLogger.isWarningEnabled());
       	assertTrue(myLogger.isInfoEnabled());
       	assertFalse(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	myLogger.setLevel( Logger.WARNING );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertTrue(myLogger.isWarningEnabled());
       	assertFalse(myLogger.isInfoEnabled());
       	assertFalse(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	myLogger.setLevel( Logger.ERROR );
    	assertTrue(myLogger.isFatalEnabled());
       	assertTrue(myLogger.isErrorEnabled());
       	assertFalse(myLogger.isWarningEnabled());
       	assertFalse(myLogger.isInfoEnabled());
       	assertFalse(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	myLogger.setLevel( Logger.FATAL );
    	assertTrue(myLogger.isFatalEnabled());
       	assertFalse(myLogger.isErrorEnabled());
       	assertFalse(myLogger.isWarningEnabled());
       	assertFalse(myLogger.isInfoEnabled());
       	assertFalse(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	myLogger.setLevel( Logger.OFF );
    	assertFalse(myLogger.isFatalEnabled());
       	assertFalse(myLogger.isErrorEnabled());
       	assertFalse(myLogger.isWarningEnabled());
       	assertFalse(myLogger.isInfoEnabled());
       	assertFalse(myLogger.isDebugEnabled());
       	assertFalse(myLogger.isTraceEnabled());
       	
       	// Set the logging level back to whatever it is configured to be.
       	myLogger.setLevel( ESAPI.securityConfiguration().getLogLevel() );
       	
       	// Normally, the default is Logger.WARNING, but if the default was changed, these tests would fail,
       	// so there are commented out for now. But you can enable to test.
       	//assertTrue(myLogger.isWarningEnabled());
       	//assertTrue(myLogger.isInfoEnabled());
    }

    
    /**
	 * Test of info method, of class org.owasp.esapi.Logger.
	 */
    public void testInfo() {
        System.out.println("info");
        ESAPI.getLogger( "mod" ).info(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).info(Logger.SECURITY, true, "test message", null );
        ESAPI.getLogger( "mod" ).info(Logger.SECURITY, true, "%3escript%3f test message", null );
        ESAPI.getLogger( "mod" ).info(Logger.SECURITY, true, "<script> test message", null );
    }

    /**
	 * Test of trace method, of class org.owasp.esapi.Logger.
	 */
    public void testTrace() {
        System.out.println("trace");
        ESAPI.getLogger( "mod" ).trace(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).trace(Logger.SECURITY, true, "test message", null );
    }

    /**
	 * Test of debug method, of class org.owasp.esapi.Logger.
	 */
    public void testDebug() {
        System.out.println("debug");
        ESAPI.getLogger( "mod" ).debug(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).debug(Logger.SECURITY, true, "test message", null );
    }

    /**
	 * Test of error method, of class org.owasp.esapi.Logger.
	 */
    public void testError() {
        System.out.println("error");
        ESAPI.getLogger( "mod" ).error(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).error(Logger.SECURITY, true, "test message", null );
    }

    /**
	 * Test of warning method, of class org.owasp.esapi.Logger.
	 */
    public void testWarning() {
        System.out.println("warning");
        ESAPI.getLogger( "mod" ).warning(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).warning(Logger.SECURITY, true, "test message", null );
    }

    /**
	 * Test of fatal method, of class org.owasp.esapi.Logger.
	 */
    public void testFatal() {
        System.out.println("fatal");
        ESAPI.getLogger( "mod" ).fatal(Logger.SECURITY, true, "test message" );
        ESAPI.getLogger( "mod" ).fatal(Logger.SECURITY, true, "test message", null );
    }
    
}
