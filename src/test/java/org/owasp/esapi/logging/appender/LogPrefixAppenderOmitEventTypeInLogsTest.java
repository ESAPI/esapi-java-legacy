package org.owasp.esapi.logging.appender;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.SecurityConfigurationWrapper;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.owasp.esapi.PropNames.OMIT_EVENT_TYPE_IN_LOGS;
import static org.powermock.api.mockito.PowerMockito.whenNew;

@RunWith(PowerMockRunner.class)
@PrepareForTest(LogPrefixAppender.class)
public class LogPrefixAppenderOmitEventTypeInLogsTest {
    private static final String EMPTY_RESULT = "   ";
    private static final String ETL_RESULT = "EVENT_TYPE";
    private static final String CIS_RESULT = "CLIENT_INFO";
    private static final String UIS_RESULT = "USER_INFO";
    private static final String SIS_RESULT = "SERVER_INFO";

    @Rule
    public TestName testName = new TestName();

    private String testLoggerName = testName.getMethodName() + "-LOGGER";
    private String testLogMessage =  testName.getMethodName() + "-MESSAGE";
    private String testApplicationName = testName.getMethodName() + "-APPLICATION_NAME";
    private EventType testEventType = Logger.EVENT_UNSPECIFIED;

    private EventTypeLogSupplier etlsSpy;
    private ClientInfoSupplier cisSpy;
    private UserInfoSupplier uisSpy;
    private ServerInfoSupplier sisSpy;

    private static class ConfOverride extends SecurityConfigurationWrapper {
        private final boolean desiredReturn;

        ConfOverride(SecurityConfiguration orig, boolean desiredReturn) {
            super(orig);
            this.desiredReturn = desiredReturn;
        }

        @Override
        public Boolean getBooleanProp(String propName) {
            // Would it be better making this file a static import?
            if (propName.equals(OMIT_EVENT_TYPE_IN_LOGS)) {
                return desiredReturn;
            } else {
                return false;
            }
        }
    }

    @Before
    public void buildSupplierSpies() {
        etlsSpy = spy(new EventTypeLogSupplier(Logger.EVENT_UNSPECIFIED));
        uisSpy = spy(new UserInfoSupplier());
        cisSpy = spy(new ClientInfoSupplier());
        sisSpy = spy(new ServerInfoSupplier(testName.getMethodName()));

        testLoggerName = testName.getMethodName() + "-LOGGER";
        testLogMessage =  testName.getMethodName() + "-MESSAGE";
        testApplicationName =  testName.getMethodName() + "-APPLICATION_NAME";

        ESAPI.override(
                new LogPrefixAppenderOmitEventTypeInLogsTest.ConfOverride(ESAPI.securityConfiguration(), true)
        );
    }
    @Test
    public void testLongContentWithOmitEventTypeInLogs() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, EMPTY_RESULT, EMPTY_RESULT, "");
    }

    @Test
    public void testLongContentWithOmitEventTypeInLogsAndUserInfo() throws Exception {
        runTest(ETL_RESULT, UIS_RESULT, EMPTY_RESULT, EMPTY_RESULT, "[USER_INFO]");
    }

    @Test
    public void testLongContentWithOmitEventTypeInLogsAndClientInfo() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, CIS_RESULT, EMPTY_RESULT, "[CLIENT_INFO]");
    }

    @Test
    public void testLongContentWithOmitEventTypeInLogsAndServerInfo() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, EMPTY_RESULT, SIS_RESULT, "[-> SERVER_INFO]");
    }

    private void runTest(String typeResult, String userResult, String clientResult, String serverResult, String exResult) throws Exception{
        when(etlsSpy.get()).thenReturn(typeResult);
        when(uisSpy.get()).thenReturn(userResult);
        when(cisSpy.get()).thenReturn(clientResult);
        when(sisSpy.get()).thenReturn(serverResult);

        whenNew(EventTypeLogSupplier.class).withArguments(testEventType).thenReturn(etlsSpy);
        whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
        whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
        whenNew(ServerInfoSupplier.class).withArguments(testLoggerName).thenReturn(sisSpy);

        //Since everything is mocked these booleans don't much matter aside from the later verifies
        LogPrefixAppender lpa = new LogPrefixAppender(false, false, false, false, null);

        String actualResult =   lpa.appendTo(testLoggerName, testEventType, testLogMessage);

        StringBuilder expectedResult = new StringBuilder();
        if (!exResult.isEmpty()) {
            expectedResult.append(exResult);
            expectedResult.append(" ");
        }
        expectedResult.append(testName.getMethodName());
        expectedResult.append("-MESSAGE");

        assertEquals(expectedResult.toString() , actualResult);
    }
}
