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
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.AuthenticationException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * The Class LoggerTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class Log4JLoggerTest extends TestCase {

	private static int testCount = 0;
	
	private static Logger testLogger = null;

	
    /**
	 * Instantiates a new logger test.
	 * 
	 * @param testName the test name
	 */
    public Log4JLoggerTest(String testName) {
        super(testName);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void setUp() throws Exception {
    	ESAPI.setLogFactory( new Log4JLogFactory() );
    	//This ensures a clean logger between tests
    	testLogger = ESAPI.getLogger( "test" + testCount++ );
    	System.out.println("Test logger: " + testLogger);
    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    	//this helps, with garbage collection
    	testLogger = null;
    }

    /**
	 * Suite.
	 * 
	 * @return the test
	 */
    public static Test suite() {
        TestSuite suite = new TestSuite(Log4JLoggerTest.class);    
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
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
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
        
        // The following tests that the default logging level is set to WARNING. Since the default might be changed
        // in the ESAPI security configuration file, these are commented out.
//       	assertTrue(testLogger.isWarningEnabled());
//       	assertFalse(testLogger.isInfoEnabled());

        // First, test all the different logging levels
        testLogger.setLevel( Logger.ALL );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertTrue(testLogger.isWarningEnabled());
       	assertTrue(testLogger.isInfoEnabled());
       	assertTrue(testLogger.isDebugEnabled());
       	assertTrue(testLogger.isTraceEnabled());

       	testLogger.setLevel( Logger.TRACE );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertTrue(testLogger.isWarningEnabled());
       	assertTrue(testLogger.isInfoEnabled());
       	assertTrue(testLogger.isDebugEnabled());
       	assertTrue(testLogger.isTraceEnabled());

       	testLogger.setLevel( Logger.DEBUG );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertTrue(testLogger.isWarningEnabled());
       	assertTrue(testLogger.isInfoEnabled());
       	assertTrue(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	testLogger.setLevel( Logger.INFO );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertTrue(testLogger.isWarningEnabled());
       	assertTrue(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	testLogger.setLevel( Logger.WARNING );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertTrue(testLogger.isWarningEnabled());
       	assertFalse(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	testLogger.setLevel( Logger.ERROR );
    	assertTrue(testLogger.isFatalEnabled());
       	assertTrue(testLogger.isErrorEnabled());
       	assertFalse(testLogger.isWarningEnabled());
       	assertFalse(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	testLogger.setLevel( Logger.FATAL );
    	assertTrue(testLogger.isFatalEnabled());
       	assertFalse(testLogger.isErrorEnabled());
       	assertFalse(testLogger.isWarningEnabled());
       	assertFalse(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	testLogger.setLevel( Logger.OFF );
    	assertFalse(testLogger.isFatalEnabled());
       	assertFalse(testLogger.isErrorEnabled());
       	assertFalse(testLogger.isWarningEnabled());
       	assertFalse(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	//Now test to see if a change to the logging level in one log affects other logs
       	Logger newLogger = ESAPI.getLogger( "test_num2" );
       	testLogger.setLevel( Logger.OFF );
       	newLogger.setLevel( Logger.INFO );
    	assertFalse(testLogger.isFatalEnabled());
       	assertFalse(testLogger.isErrorEnabled());
       	assertFalse(testLogger.isWarningEnabled());
       	assertFalse(testLogger.isInfoEnabled());
       	assertFalse(testLogger.isDebugEnabled());
       	assertFalse(testLogger.isTraceEnabled());
       	
       	assertTrue(newLogger.isFatalEnabled());
       	assertTrue(newLogger.isErrorEnabled());
       	assertTrue(newLogger.isWarningEnabled());
       	assertTrue(newLogger.isInfoEnabled());
       	assertFalse(newLogger.isDebugEnabled());
       	assertFalse(newLogger.isTraceEnabled());
    }

    
    /**
	 * Test of info method, of class org.owasp.esapi.Logger.
	 */
    public void testInfo() {
        System.out.println("info");
        testLogger.info(Logger.SECURITY_SUCCESS, "test message" );
        testLogger.info(Logger.SECURITY_SUCCESS, "test message", null );
        testLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", null );
        testLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", null );
    }

    /**
	 * Test of trace method, of class org.owasp.esapi.Logger.
	 */
    public void testTrace() {
        System.out.println("trace");
        testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace" );
        testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace", null );
    }

    /**
	 * Test of debug method, of class org.owasp.esapi.Logger.
	 */
    public void testDebug() {
        System.out.println("debug");
        testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug" );
        testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug", null );
    }

    /**
	 * Test of error method, of class org.owasp.esapi.Logger.
	 */
    public void testError() {
        System.out.println("error");
        testLogger.error(Logger.SECURITY_SUCCESS, "test message error" );
        testLogger.error(Logger.SECURITY_SUCCESS, "test message error", null );
    }

    /**
	 * Test of warning method, of class org.owasp.esapi.Logger.
	 */
    public void testWarning() {
        System.out.println("warning");
        testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning" );
        testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning", null );
    }

    /**
	 * Test of fatal method, of class org.owasp.esapi.Logger.
	 */
    public void testFatal() {
        System.out.println("fatal");
        testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal" );
        testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", null );
    }
}
