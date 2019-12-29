package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
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
	@Rule
	public TestName testName = new TestName();

	private EventTypeLogSupplier etlsSpy;
	private String etlsSpyGet = "EVENT_TYPE";

	private ClientInfoSupplier cisSpy;
    private String cisSpyGet = "CLIENT_INFO";
    
    private UserInfoSupplier uisSpy;
    private String uisSpyGet = "USER_INFO";

	private ServerInfoSupplier sisSpy;
	private String sisSpyGet = "SERVER_INFO";

	@Before
	public void buildSupplierSpies() {
		etlsSpy = spy(new EventTypeLogSupplier(Logger.EVENT_UNSPECIFIED));
		uisSpy = spy(new UserInfoSupplier());
		cisSpy = spy(new ClientInfoSupplier());
		sisSpy = spy(new ServerInfoSupplier(testName.getMethodName()));

		when(etlsSpy.get()).thenReturn(etlsSpyGet);
		when(uisSpy.get()).thenReturn(uisSpyGet);
		when(cisSpy.get()).thenReturn(cisSpyGet);
		when(sisSpy.get()).thenReturn(sisSpyGet);
	}

	@Test
	public void verifyDelegatePassthroughCreation() throws Exception {
		ArgumentCaptor<EventType> eventTypeCapture = ArgumentCaptor.forClass(EventType.class);
		ArgumentCaptor<String> logNameCapture = ArgumentCaptor.forClass(String.class);
		whenNew(EventTypeLogSupplier.class).withArguments(eventTypeCapture.capture()).thenReturn(etlsSpy);
		whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
		whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
		whenNew(ServerInfoSupplier.class).withArguments(logNameCapture.capture()).thenReturn(sisSpy);

		LogPrefixAppender lpa = new LogPrefixAppender(true, true, true, true, testName.getMethodName() + "-APPLICATION");
		String result = lpa.appendTo(testName.getMethodName() + "-LOGGER", Logger.EVENT_UNSPECIFIED,
				testName.getMethodName() + "-MESSAGE");

		// Based on the forced returns in the before block
		assertEquals("[EVENT_TYPE USER_INFO:CLIENT_INFO -> SERVER_INFO] " + testName.getMethodName() + "-MESSAGE", result);

		assertEquals(Logger.EVENT_UNSPECIFIED, eventTypeCapture.getValue());
		assertEquals(testName.getMethodName() + "-LOGGER", logNameCapture.getValue());

		verify(etlsSpy, times(1)).get();
		verify(uisSpy, times(1)).get();
		verify(cisSpy, times(1)).get();
		verify(sisSpy, times(1)).get();

		verify(uisSpy, times(1)).setLogUserInfo(true);
		verify(cisSpy, times(1)).setLogClientInfo(true);
		verify(sisSpy, times(1)).setLogServerIp(true);
		verify(sisSpy, times(1)).setLogApplicationName(true, testName.getMethodName() + "-APPLICATION");

		verifyNoMoreInteractions(etlsSpy, uisSpy, cisSpy, sisSpy);
	}

	@Test
	public void verifyDelegatePassthroughCreation2() throws Exception {
		ArgumentCaptor<EventType> eventTypeCapture = ArgumentCaptor.forClass(EventType.class);
		ArgumentCaptor<String> logNameCapture = ArgumentCaptor.forClass(String.class);
		whenNew(EventTypeLogSupplier.class).withArguments(eventTypeCapture.capture()).thenReturn(etlsSpy);
		whenNew(UserInfoSupplier.class).withNoArguments().thenReturn(uisSpy);
		whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
		whenNew(ServerInfoSupplier.class).withArguments(logNameCapture.capture()).thenReturn(sisSpy);

		LogPrefixAppender lpa = new LogPrefixAppender(false, false, false, false, null);
		String result = lpa.appendTo(testName.getMethodName() + "-LOGGER", Logger.EVENT_UNSPECIFIED,
				testName.getMethodName() + "-MESSAGE");

		// Based on the forced returns in the before block
		assertEquals("[EVENT_TYPE USER_INFO:CLIENT_INFO -> SERVER_INFO] " + testName.getMethodName() + "-MESSAGE", result);

		assertEquals(Logger.EVENT_UNSPECIFIED, eventTypeCapture.getValue());
		assertEquals(testName.getMethodName() + "-LOGGER", logNameCapture.getValue());

		verify(etlsSpy, times(1)).get();
		verify(uisSpy, times(1)).get();
		verify(cisSpy, times(1)).get();
		verify(sisSpy, times(1)).get();

		verify(uisSpy, times(1)).setLogUserInfo(false);
		verify(cisSpy, times(1)).setLogClientInfo(false);
		verify(sisSpy, times(1)).setLogServerIp(false);
		verify(sisSpy, times(1)).setLogApplicationName(false, null);

		verifyNoMoreInteractions(etlsSpy, uisSpy, cisSpy, sisSpy);
	}

}
