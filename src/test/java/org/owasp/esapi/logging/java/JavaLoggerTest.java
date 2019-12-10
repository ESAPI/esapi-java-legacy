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
 * @created 2018
 */

package org.owasp.esapi.logging.java;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;

public class JavaLoggerTest {
	@Rule
    public TestName testName = new TestName();
	
    private static final String MSG = JavaLoggerTest.class.getSimpleName();
    
    private JavaLogBridge mockBridge = Mockito.mock(JavaLogBridge.class);
    private java.util.logging.Logger javaLogSpy;
    
    private Throwable testEx = new Throwable(MSG + "_Exception");
    private Logger testLogger;

    @Before
    public void setup() {
    	 java.util.logging.Logger wrappedLogger = java.util.logging.Logger.getLogger(testName.getMethodName());
         javaLogSpy = Mockito.spy(wrappedLogger);
    	 testLogger = new JavaLogger(javaLogSpy, mockBridge, Logger.ALL);
    }
    
    @Test
    public void testLevelEnablement() {
        testLogger.setLevel(Logger.INFO);
        
        Assert.assertFalse(testLogger.isFatalEnabled());
        Assert.assertFalse(testLogger.isErrorEnabled());
        Assert.assertFalse(testLogger.isWarningEnabled());
        Assert.assertTrue(testLogger.isInfoEnabled());
        Assert.assertTrue(testLogger.isDebugEnabled());
        Assert.assertTrue(testLogger.isTraceEnabled());
        
        Assert.assertEquals(Logger.INFO, testLogger.getESAPILevel());
    }
    
    @Test
    public void testAllLevelEnablement() {
        testLogger.setLevel(Logger.ALL);
        
        Assert.assertTrue(testLogger.isFatalEnabled());
        Assert.assertTrue(testLogger.isErrorEnabled());
        Assert.assertTrue(testLogger.isWarningEnabled());
        Assert.assertTrue(testLogger.isInfoEnabled());
        Assert.assertTrue(testLogger.isDebugEnabled());
        Assert.assertTrue(testLogger.isTraceEnabled());
    }

    @Test
    public void testOffLevelEnablement() {
        testLogger.setLevel(Logger.OFF);
        
        Assert.assertFalse(testLogger.isFatalEnabled());
        Assert.assertFalse(testLogger.isErrorEnabled());
        Assert.assertFalse(testLogger.isWarningEnabled());
        Assert.assertFalse(testLogger.isInfoEnabled());
        Assert.assertFalse(testLogger.isDebugEnabled());
        Assert.assertFalse(testLogger.isTraceEnabled());
    }
    @Test
    public void testFatalWithMessage() {
        testLogger.fatal(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.FATAL, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testFatalWithMessageAndThrowable() {
        testLogger.fatal(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.FATAL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testFatalWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.fatal(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.FATAL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testFatalWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.fatal(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.FATAL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testErrorWithMessage() {
        testLogger.error(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.ERROR, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testErrorWithMessageAndThrowable() {
        testLogger.error(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.ERROR, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testErrorWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.error(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.ERROR, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testErrorWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.error(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.ERROR, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testWarnWithMessage() {
        testLogger.warning(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.WARNING, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testWarnWithMessageAndThrowable() {
        testLogger.warning(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.WARNING, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testWarnWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.warning(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.WARNING, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testWarnWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.warning(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.WARNING, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testInfoWithMessage() {
        testLogger.info(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.INFO, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testInfoWithMessageAndThrowable() {
        testLogger.info(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.INFO, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testInfoWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.info(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.INFO, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testInfoWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.info(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.INFO, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testDebugWithMessage() {
        testLogger.debug(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.DEBUG, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testDebugWithMessageAndThrowable() {
        testLogger.debug(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.DEBUG, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testDebugWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.debug(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.DEBUG, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testDebugWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.debug(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.DEBUG, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testTraceWithMessage() {
        testLogger.trace(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.TRACE, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testTraceWithMessageAndThrowable() {
        testLogger.trace(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.TRACE, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testTraceWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.trace(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.TRACE, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testTraceWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.trace(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.TRACE, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testAlwaysWithMessage() {
        testLogger.always(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, MSG);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testAlwaysWithMessageAndThrowable() {
        testLogger.always(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        
        Mockito.verify(mockBridge, Mockito.times(1)).log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    
    @Test
    public void testAlwaysWithMessageDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.always(Logger.EVENT_UNSPECIFIED, MSG);
        
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
    @Test
    public void testAlwaysWithMessageAndThrowableDisabled() {
        testLogger.setLevel(Logger.OFF);
        testLogger.always(Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verify(mockBridge, Mockito.times(0)).log(javaLogSpy, Logger.ALL, Logger.EVENT_UNSPECIFIED, MSG, testEx);
        Mockito.verifyNoMoreInteractions(mockBridge, javaLogSpy);
    }
}
