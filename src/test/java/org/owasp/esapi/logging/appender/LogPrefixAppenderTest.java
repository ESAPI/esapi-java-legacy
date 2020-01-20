package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(LogPrefixAppender.class)
public class LogPrefixAppenderTest {
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

    @Before
    public void buildSupplierSpies() {
        etlsSpy = spy(new EventTypeLogSupplier(Logger.EVENT_UNSPECIFIED));
        uisSpy = spy(new UserInfoSupplier());
        cisSpy = spy(new ClientInfoSupplier());
        sisSpy = spy(new ServerInfoSupplier(testName.getMethodName()));
        
        testLoggerName = testName.getMethodName() + "-LOGGER";
        testLogMessage =  testName.getMethodName() + "-MESSAGE";
        testApplicationName =  testName.getMethodName() + "-APPLICATION_NAME";
    }
    @Test
    public void testCtrArgTruePassthroughToDelegates() throws Exception {
        when(etlsSpy.get()).thenReturn(ETL_RESULT);
        when(uisSpy.get()).thenReturn(UIS_RESULT);
        when(cisSpy.get()).thenReturn(CIS_RESULT);
        when(sisSpy.get()).thenReturn(SIS_RESULT);

        whenNew(EventTypeLogSupplier.class).withArguments(testEventType).thenReturn(etlsSpy);
        whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
        whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
        whenNew(ServerInfoSupplier.class).withArguments(testLoggerName).thenReturn(sisSpy);

        LogPrefixAppender lpa = new LogPrefixAppender(true, true,true,true, testApplicationName);
        lpa.appendTo(testLoggerName, testEventType, testLogMessage);

        verify(uisSpy, times(1)).setLogUserInfo(true);
        verify(cisSpy, times(1)).setLogClientInfo(true);
        verify(sisSpy, times(1)).setLogServerIp(true);
        verify(sisSpy, times(1)).setLogApplicationName(true, testApplicationName);
    }
    
    @Test
    public void testCtrArgFalsePassthroughToDelegates() throws Exception {
        when(etlsSpy.get()).thenReturn(ETL_RESULT);
        when(uisSpy.get()).thenReturn(UIS_RESULT);
        when(cisSpy.get()).thenReturn(CIS_RESULT);
        when(sisSpy.get()).thenReturn(SIS_RESULT);

        whenNew(EventTypeLogSupplier.class).withArguments(testEventType).thenReturn(etlsSpy);
        whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
        whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
        whenNew(ServerInfoSupplier.class).withArguments(testLoggerName).thenReturn(sisSpy);

        LogPrefixAppender lpa = new LogPrefixAppender(false, false, false, false, null);
        lpa.appendTo(testLoggerName, testEventType, testLogMessage);

        verify(uisSpy, times(1)).setLogUserInfo(false);
        verify(cisSpy, times(1)).setLogClientInfo(false);
        verify(sisSpy, times(1)).setLogServerIp(false);
        verify(sisSpy, times(1)).setLogApplicationName(false, null);
    }
    
    @Test
    public void testDelegateCtrArgs() throws Exception {
        ArgumentCaptor<EventType> eventTypeCapture = ArgumentCaptor.forClass(EventType.class);
        ArgumentCaptor<String> logNameCapture = ArgumentCaptor.forClass(String.class);
        whenNew(EventTypeLogSupplier.class).withArguments(eventTypeCapture.capture()).thenReturn(etlsSpy);
        whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
        whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
        whenNew(ServerInfoSupplier.class).withArguments(logNameCapture.capture()).thenReturn(sisSpy);

        LogPrefixAppender lpa = new LogPrefixAppender(true, true,true,true, testApplicationName);
        lpa.appendTo(testLoggerName, testEventType, testLogMessage);

        assertEquals(testEventType, eventTypeCapture.getValue());
        assertEquals(testLoggerName, logNameCapture.getValue());
    }

    @Test
    public void testLogContentWhenClientInfoEmpty() throws Exception {
        runTest(ETL_RESULT, UIS_RESULT, EMPTY_RESULT,SIS_RESULT, "[EVENT_TYPE USER_INFO -> SERVER_INFO]");
    }


    @Test
    public void testLogContentWhenUserInfoEmpty() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, CIS_RESULT,SIS_RESULT, "[EVENT_TYPE CLIENT_INFO -> SERVER_INFO]");
    }
    
    @Test
    public void testLogContentWhenClientInfoEmptyAndServerInfoEmpty() throws Exception {
        runTest(ETL_RESULT, UIS_RESULT, EMPTY_RESULT,EMPTY_RESULT, "[EVENT_TYPE USER_INFO]");
    }

    @Test
    public void testLogContentWhenUserInfoEmptyAndServerInfoEmpty() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, CIS_RESULT,EMPTY_RESULT, "[EVENT_TYPE CLIENT_INFO]");
    }

    @Test
    public void testLogContentWhenUserInfoAndClientInfoEmpty() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, EMPTY_RESULT, SIS_RESULT, "[EVENT_TYPE -> SERVER_INFO]");
    }

    @Test
    public void testLogContentWhenServerInfoEmpty() throws Exception {
        runTest(ETL_RESULT, UIS_RESULT, CIS_RESULT, EMPTY_RESULT, "[EVENT_TYPE USER_INFO:CLIENT_INFO]");
    }
    
    @Test
    public void testLogContentWhenUserInfoEmptyAndClientInfoEmptyAndServerInfoEmpty() throws Exception {
        runTest(ETL_RESULT, EMPTY_RESULT, EMPTY_RESULT, EMPTY_RESULT, "[EVENT_TYPE]");
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
        String result =   lpa.appendTo(testLoggerName, testEventType, testLogMessage);
        
        assertEquals(exResult + " " + testName.getMethodName() + "-MESSAGE", result);
    }
}
