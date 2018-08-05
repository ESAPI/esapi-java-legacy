package org.owasp.esapi.logging.slf4j;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.helpers.BasicMarkerFactory;

public class Slf4JLogHandlersTest {

    private Logger mockLogger = Mockito.mock(Logger.class);
    @Rule
    public TestName testName = new TestName();

    private Marker marker = new BasicMarkerFactory().getMarker(Slf4JLogHandlersTest.class.getSimpleName());
    private Throwable testException = new Throwable("Expected for testing");

    @Test
    public void testErrorDelegation() {
        Slf4JLogHandlers.ERROR.isEnabled(mockLogger);
        Slf4JLogHandlers.ERROR.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogHandlers.ERROR.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isErrorEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).error(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }

    @Test
    public void testWarnDelegation() {
        Slf4JLogHandlers.WARN.isEnabled(mockLogger);
        Slf4JLogHandlers.WARN.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogHandlers.WARN.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isWarnEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).warn(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testInfoDelegation() {
        Slf4JLogHandlers.INFO.isEnabled(mockLogger);
        Slf4JLogHandlers.INFO.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogHandlers.INFO.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isInfoEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).info(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testDebugDelegation() {
        Slf4JLogHandlers.DEBUG.isEnabled(mockLogger);
        Slf4JLogHandlers.DEBUG.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogHandlers.DEBUG.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isDebugEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).debug(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
    @Test
    public void testTraceDelegation() {
        Slf4JLogHandlers.TRACE.isEnabled(mockLogger);
        Slf4JLogHandlers.TRACE.log(mockLogger, marker, testName.getMethodName());
        Slf4JLogHandlers.TRACE.log(mockLogger, marker, testName.getMethodName(), testException);

        Mockito.verify(mockLogger, Mockito.times(1)).isTraceEnabled();
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName.getMethodName());
        Mockito.verify(mockLogger, Mockito.times(1)).trace(marker, testName.getMethodName(), testException);
        Mockito.verifyNoMoreInteractions(mockLogger);
    }
}
