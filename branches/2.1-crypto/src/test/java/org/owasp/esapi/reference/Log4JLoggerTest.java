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
import org.owasp.esapi.http.MockHttpServletRequest;
import org.owasp.esapi.http.MockHttpServletResponse;

/**
 * The Class LoggerTest.
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @author August Detlefsen (augustd at codemagi dot com) <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 */
public class Log4JLoggerTest extends TestCase {
	private static int testCount = 0;
	
	private static Logger testLogger = null;

	//a logger for explicit tests of log4j logging methods
	private static Log4JLogger log4JLogger = null;

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
		//override default log configuration in ESAPI.properties to use Log4JLogFactory
        UnitTestSecurityConfiguration tmpConfig = new UnitTestSecurityConfiguration((DefaultSecurityConfiguration) ESAPI.securityConfiguration());
        tmpConfig.setLogImplementation( Log4JLogFactory.class.getName() );
        ESAPI.override(tmpConfig);

    	//This ensures a clean logger between tests
    	testLogger = ESAPI.getLogger( "test ExampleExtendedLog4JLogFactory: " + testCount++ );
    	System.out.println("Test ExampleExtendedLog4JLogFactory logger: " + testLogger);

		//declare this one as Log4JLogger to be able to use Log4J logging methods
		log4JLogger = (Log4JLogger)ESAPI.getLogger( "test Log4JLogFactory: " + testCount);
		System.out.println("Test Log4JLogFactory logger: " + log4JLogger);

    }

    /**
     * {@inheritDoc}
     * @throws Exception
     */
    protected void tearDown() throws Exception {
    	//this helps, with garbage collection
    	testLogger = null;
		log4JLogger = null;

		ESAPI.override(null);
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
	 * test of loggers without setting explicit log levels
	 * (log levels set from log4j.xml configuration)
	 */
	public void testLogLevels() {

		Logger traceLogger			= ESAPI.getLogger("org.owasp.esapi.reference.TestTrace");
		Logger debugLogger			= ESAPI.getLogger("org.owasp.esapi.reference.TestDebug");
		Logger infoLogger			= ESAPI.getLogger("org.owasp.esapi.reference.TestInfo");
		Logger errorLogger			= ESAPI.getLogger("org.owasp.esapi.reference.TestError");
		Logger warningLogger		= ESAPI.getLogger("org.owasp.esapi.reference.TestWarning");
		Logger fatalLogger			= ESAPI.getLogger("org.owasp.esapi.reference.TestFatal");
		Logger unspecifiedLogger	= ESAPI.getLogger("org.owasp.esapi.reference");  //should use package-wide log level configuration (info)


		//traceLogger - all log levels should be enabled
		assertTrue(traceLogger.isTraceEnabled());
		assertTrue(traceLogger.isDebugEnabled());
		assertTrue(traceLogger.isInfoEnabled());
		assertTrue(traceLogger.isWarningEnabled());
		assertTrue(traceLogger.isErrorEnabled());
		assertTrue(traceLogger.isFatalEnabled());

		//debugLogger - all log levels should be enabled EXCEPT trace
		assertFalse(debugLogger.isTraceEnabled());
		assertTrue(debugLogger.isDebugEnabled());
		assertTrue(debugLogger.isInfoEnabled());
		assertTrue(debugLogger.isWarningEnabled());
		assertTrue(debugLogger.isErrorEnabled());
		assertTrue(debugLogger.isFatalEnabled());

		//infoLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(infoLogger.isTraceEnabled());
		assertFalse(infoLogger.isDebugEnabled());
		assertTrue(infoLogger.isInfoEnabled());
		assertTrue(infoLogger.isWarningEnabled());
		assertTrue(infoLogger.isErrorEnabled());
		assertTrue(infoLogger.isFatalEnabled());

		//warningLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(warningLogger.isTraceEnabled());
		assertFalse(warningLogger.isDebugEnabled());
		assertFalse(warningLogger.isInfoEnabled());
		assertTrue(warningLogger.isWarningEnabled());
		assertTrue(warningLogger.isErrorEnabled());
		assertTrue(warningLogger.isFatalEnabled());

		//errorLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(errorLogger.isTraceEnabled());
		assertFalse(errorLogger.isDebugEnabled());
		assertFalse(errorLogger.isInfoEnabled());
		assertFalse(errorLogger.isWarningEnabled());
		assertTrue(errorLogger.isErrorEnabled());
		assertTrue(errorLogger.isFatalEnabled());

		//fatalLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(fatalLogger.isTraceEnabled());
		assertFalse(fatalLogger.isDebugEnabled());
		assertFalse(fatalLogger.isInfoEnabled());
		assertFalse(fatalLogger.isWarningEnabled());
		assertFalse(fatalLogger.isErrorEnabled());
		assertTrue(fatalLogger.isFatalEnabled());

		//unspecifiedLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(unspecifiedLogger.isTraceEnabled());
		assertFalse(unspecifiedLogger.isDebugEnabled());
		assertTrue(unspecifiedLogger.isInfoEnabled());
		assertTrue(unspecifiedLogger.isWarningEnabled());
		assertTrue(unspecifiedLogger.isErrorEnabled());
		assertTrue(unspecifiedLogger.isFatalEnabled());
	}

	/**
	 * test of loggers without setting explicit log levels
	 * (log levels set from log4j.xml configuration)
	 */
	public void testLogLevelsWithClass() {

		Logger traceLogger			= ESAPI.getLogger(TestTrace.class);
		Logger debugLogger			= ESAPI.getLogger(TestDebug.class);
		Logger infoLogger			= ESAPI.getLogger(TestInfo.class);
		Logger errorLogger			= ESAPI.getLogger(TestError.class);
		Logger warningLogger		= ESAPI.getLogger(TestWarning.class);
		Logger fatalLogger			= ESAPI.getLogger(TestFatal.class);
		Logger unspecifiedLogger	= ESAPI.getLogger(TestUnspecified.class);  //should use package-wide log level configuration (info)

		//traceLogger - all log levels should be enabled
		assertTrue(traceLogger.isTraceEnabled());
		assertTrue(traceLogger.isDebugEnabled());
		assertTrue(traceLogger.isInfoEnabled());
		assertTrue(traceLogger.isWarningEnabled());
		assertTrue(traceLogger.isErrorEnabled());
		assertTrue(traceLogger.isFatalEnabled());

		//debugLogger - all log levels should be enabled EXCEPT trace
		assertFalse(debugLogger.isTraceEnabled());
		assertTrue(debugLogger.isDebugEnabled());
		assertTrue(debugLogger.isInfoEnabled());
		assertTrue(debugLogger.isWarningEnabled());
		assertTrue(debugLogger.isErrorEnabled());
		assertTrue(debugLogger.isFatalEnabled());

		//infoLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(infoLogger.isTraceEnabled());
		assertFalse(infoLogger.isDebugEnabled());
		assertTrue(infoLogger.isInfoEnabled());
		assertTrue(infoLogger.isWarningEnabled());
		assertTrue(infoLogger.isErrorEnabled());
		assertTrue(infoLogger.isFatalEnabled());

		//warningLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(warningLogger.isTraceEnabled());
		assertFalse(warningLogger.isDebugEnabled());
		assertFalse(warningLogger.isInfoEnabled());
		assertTrue(warningLogger.isWarningEnabled());
		assertTrue(warningLogger.isErrorEnabled());
		assertTrue(warningLogger.isFatalEnabled());

		//errorLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(errorLogger.isTraceEnabled());
		assertFalse(errorLogger.isDebugEnabled());
		assertFalse(errorLogger.isInfoEnabled());
		assertFalse(errorLogger.isWarningEnabled());
		assertTrue(errorLogger.isErrorEnabled());
		assertTrue(errorLogger.isFatalEnabled());

		//fatalLogger - all log levels should be enabled EXCEPT etc.
		assertFalse(fatalLogger.isTraceEnabled());
		assertFalse(fatalLogger.isDebugEnabled());
		assertFalse(fatalLogger.isInfoEnabled());
		assertFalse(fatalLogger.isWarningEnabled());
		assertFalse(fatalLogger.isErrorEnabled());
		assertTrue(fatalLogger.isFatalEnabled());

		//unspecifiedLogger - all log levels should be enabled EXCEPT trace and debug
		assertFalse(unspecifiedLogger.isTraceEnabled());
		assertFalse(unspecifiedLogger.isDebugEnabled());
		assertTrue(unspecifiedLogger.isInfoEnabled());
		assertTrue(unspecifiedLogger.isWarningEnabled());
		assertTrue(unspecifiedLogger.isErrorEnabled());
		assertTrue(unspecifiedLogger.isFatalEnabled());
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

        log4JLogger.info("test message" );
        log4JLogger.info("test message", null );
        log4JLogger.info("%3escript%3f test message", null );
        log4JLogger.info("<script> test message", null );

        log4JLogger.info(Logger.SECURITY_SUCCESS, "test message" );
        log4JLogger.info(Logger.SECURITY_SUCCESS, "test message", null );
        log4JLogger.info(Logger.SECURITY_SUCCESS, "%3escript%3f test message", null );
        log4JLogger.info(Logger.SECURITY_SUCCESS, "<script> test message", null );
	}

    /**
	 * Test of trace method, of class org.owasp.esapi.Logger.
	 */
    public void testTrace() {
        System.out.println("trace");
        testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace" );
        testLogger.trace(Logger.SECURITY_SUCCESS, "test message trace", null );

        log4JLogger.trace("test message trace" );
        log4JLogger.trace("test message trace", null );
	}

    /**
	 * Test of debug method, of class org.owasp.esapi.Logger.
	 */
    public void testDebug() {
        System.out.println("debug");
        testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug" );
        testLogger.debug(Logger.SECURITY_SUCCESS, "test message debug", null );

	    log4JLogger.debug("test message debug" );
		log4JLogger.debug("test message debug", null );
	}

    /**
	 * Test of error method, of class org.owasp.esapi.Logger.
	 */
    public void testError() {
        System.out.println("error");
        testLogger.error(Logger.SECURITY_SUCCESS, "test message error" );
        testLogger.error(Logger.SECURITY_SUCCESS, "test message error", null );

	    log4JLogger.error("test message error" );
		log4JLogger.error("test message error", null );
	}

    /**
	 * Test of warning method, of class org.owasp.esapi.Logger.
	 */
    public void testWarning() {
        System.out.println("warning");
        testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning" );
        testLogger.warning(Logger.SECURITY_SUCCESS, "test message warning", null );

	    log4JLogger.warn("test message warning" );
		log4JLogger.warn("test message warning", null );
    }

    /**
	 * Test of fatal method, of class org.owasp.esapi.Logger.
	 */
    public void testFatal() {
        System.out.println("fatal");
        testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal" );
        testLogger.fatal(Logger.SECURITY_SUCCESS, "test message fatal", null );

	    log4JLogger.fatal("test message fatal" );
		log4JLogger.fatal("test message fatal", null );    
	}

}
