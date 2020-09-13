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
package org.owasp.esapi.logging.java;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.mockito.Mockito;

public class JavaLogLevelHandlersTest {

    private Logger mockLogger = Mockito.mock(Logger.class);
    @Rule
    public TestName testName = new TestName();

    private Throwable testException = new Throwable("Expected for testing");

    @Test
    public void testErrorDelegation() {
        JavaLogLevelHandlers.ERROR.isEnabled(mockLogger);
        JavaLogLevelHandlers.ERROR.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.ERROR.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = ESAPICustomJavaLevel.ERROR_LEVEL;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }

    @Test
    public void testAlwaysDelegation() {
        JavaLogLevelHandlers.ALWAYS.isEnabled(mockLogger);
        JavaLogLevelHandlers.ALWAYS.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.ALWAYS.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = ESAPICustomJavaLevel.ALWAYS_LEVEL;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    
    @Test
    public void testWarnDelegation() {
        JavaLogLevelHandlers.WARNING.isEnabled(mockLogger);
        JavaLogLevelHandlers.WARNING.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.WARNING.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = Level.WARNING;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testInfoDelegation() {
        JavaLogLevelHandlers.INFO.isEnabled(mockLogger);
        JavaLogLevelHandlers.INFO.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.INFO.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = Level.INFO;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);

        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testDebugDelegation() {
        JavaLogLevelHandlers.FINE.isEnabled(mockLogger);
        JavaLogLevelHandlers.FINE.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.FINE.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = Level.FINE;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);

        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testTraceDelegation() {
        JavaLogLevelHandlers.FINEST.isEnabled(mockLogger);
        JavaLogLevelHandlers.FINEST.log(mockLogger, testName.getMethodName());
        JavaLogLevelHandlers.FINEST.log(mockLogger, testName.getMethodName(), testException);

        Level expectedJavaLevel = Level.FINEST;

        Mockito.verify(mockLogger, Mockito.times(1)).isLoggable(expectedJavaLevel);
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).log(expectedJavaLevel, testName.getMethodName(), testException);

        Mockito.verifyNoMoreInteractions(mockLogger);
    }
}
