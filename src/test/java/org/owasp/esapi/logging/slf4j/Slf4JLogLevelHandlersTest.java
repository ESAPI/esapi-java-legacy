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
package org.owasp.esapi.logging.slf4j;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.helpers.BasicMarkerFactory;

public class Slf4JLogLevelHandlersTest {

    private Logger mockLogger = Mockito.mock(Logger.class);
    @Rule
    public TestName testName = new TestName();

    private Marker marker = new BasicMarkerFactory().getMarker(Slf4JLogLevelHandlersTest.class.getSimpleName());
    private Throwable testException = new Throwable("Expected for testing");

    @Test
    public void testErrorDelegation() {
        Slf4JLogLevelHandlers.ERROR.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.ERROR.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogLevelHandlers.ERROR.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isErrorEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }

    @Test
    public void testWarnDelegation() {
        Slf4JLogLevelHandlers.WARN.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.WARN.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogLevelHandlers.WARN.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isWarnEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testInfoDelegation() {
        Slf4JLogLevelHandlers.INFO.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.INFO.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogLevelHandlers.INFO.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isInfoEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testDebugDelegation() {
        Slf4JLogLevelHandlers.DEBUG.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.DEBUG.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogLevelHandlers.DEBUG.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isDebugEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testTraceDelegation() {
        Slf4JLogLevelHandlers.TRACE.isEnabled(mockLogger);
        Slf4JLogLevelHandlers.TRACE.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogLevelHandlers.TRACE.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isTraceEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
}
