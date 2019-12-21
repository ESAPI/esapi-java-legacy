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
 * @created 2019
 */
package org.owasp.esapi.logging.log4j;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.owasp.esapi.logging.log4j.Log4JLogLevelHandlers;

public class Log4JLogLevelHandlersTest {

    private Logger mockLogger = Mockito.mock(Logger.class);
    @Rule
    public TestName testName = new TestName();

    private Throwable testException = new Throwable("Expected for testing");

    @Test
    public void testFatalDelegation() {
        Log4JLogLevelHandlers.FATAL.isEnabled(mockLogger);
        Log4JLogLevelHandlers.FATAL.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.FATAL.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.FATAL);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.FATAL, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.FATAL, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }

    
    @Test
    public void testErrorDelegation() {
        Log4JLogLevelHandlers.ERROR.isEnabled(mockLogger);
        Log4JLogLevelHandlers.ERROR.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.ERROR.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.ERROR);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.ERROR, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.ERROR, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }

    @Test
    public void testWarnDelegation() {
        Log4JLogLevelHandlers.WARN.isEnabled(mockLogger);
        Log4JLogLevelHandlers.WARN.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.WARN.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.WARN);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.WARN, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.WARN, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testInfoDelegation() {
        Log4JLogLevelHandlers.INFO.isEnabled(mockLogger);
        Log4JLogLevelHandlers.INFO.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.INFO.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.INFO);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.INFO, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.INFO, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testDebugDelegation() {
        Log4JLogLevelHandlers.DEBUG.isEnabled(mockLogger);
        Log4JLogLevelHandlers.DEBUG.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.DEBUG.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.DEBUG);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.DEBUG, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.DEBUG, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testTraceDelegation() {
        Log4JLogLevelHandlers.TRACE.isEnabled(mockLogger);
        Log4JLogLevelHandlers.TRACE.log(mockLogger, testName.getMethodName());
        Log4JLogLevelHandlers.TRACE.log(mockLogger, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isEnabledFor(Level.TRACE);
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.TRACE, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(Level.TRACE, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
}
