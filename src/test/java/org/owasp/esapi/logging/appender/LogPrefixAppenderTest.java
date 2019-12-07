package org.owasp.esapi.logging.appender;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Logger.EventType;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.junit.Assert;

@RunWith(PowerMockRunner.class)
@PrepareForTest (LogPrefixAppender.class)
public class LogPrefixAppenderTest {
	@Rule
    public TestName testName = new TestName();

	private EventTypeLogSupplier etlsSpy;
	private String etlsSpyGet = "EVENT_TYPE";
	
	private ClientInfoSupplier cisSpy;
	private String cisSpyGet = "CLIENT_INFO";
	
	private ServerInfoSupplier sisSpy;
	private String sisSpyGet = "SERVER_INFO";
	
	@Before
	public void buildSupplierSpies() {
		etlsSpy = Mockito.spy(new EventTypeLogSupplier(Logger.EVENT_UNSPECIFIED));
		cisSpy = Mockito.spy(new ClientInfoSupplier());
		sisSpy = Mockito.spy(new ServerInfoSupplier(testName.getMethodName()));
		
		Mockito.when(etlsSpy.get()).thenReturn(etlsSpyGet);
		Mockito.when(cisSpy.get()).thenReturn(cisSpyGet);
		Mockito.when(sisSpy.get()).thenReturn(sisSpyGet);
	}
	
	@Test
	public void verifyDelegatePassthroughCreation() throws Exception {
		ArgumentCaptor<EventType> eventTypeCapture = ArgumentCaptor.forClass(EventType.class);
		ArgumentCaptor<String> logNameCapture = ArgumentCaptor.forClass(String.class);
		 PowerMockito.whenNew(EventTypeLogSupplier.class).withArguments(eventTypeCapture.capture()).thenReturn(etlsSpy);
		 PowerMockito.whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
		 PowerMockito.whenNew(ServerInfoSupplier.class).withArguments(logNameCapture.capture()).thenReturn(sisSpy);

		 LogPrefixAppender lpa = new LogPrefixAppender(true, true, true, testName.getMethodName()+"-APPLICATION");
		 String result = lpa.appendTo( testName.getMethodName()+"-LOGGER", Logger.EVENT_UNSPECIFIED,  testName.getMethodName()+"-MESSAGE");
		 
		 //Based on the forced returns in the before block
		 Assert.assertEquals("[EVENT_TYPE CLIENT_INFO -> SERVER_INFO] "+ testName.getMethodName()+"-MESSAGE", result);
	     
		 Assert.assertEquals(Logger.EVENT_UNSPECIFIED, eventTypeCapture.getValue());
		 Assert.assertEquals(testName.getMethodName()+"-LOGGER",logNameCapture.getValue());
		 
		 Mockito.verify(etlsSpy, Mockito.times(1)).get();
		 Mockito.verify(cisSpy, Mockito.times(1)).get();
		 Mockito.verify(sisSpy, Mockito.times(1)).get();
		 
		 Mockito.verify(cisSpy, Mockito.times(1)).setLogUserInfo(true);
		 Mockito.verify(sisSpy, Mockito.times(1)).setLogServerIp(true);
		 Mockito.verify(sisSpy, Mockito.times(1)).setLogApplicationName(true, testName.getMethodName()+"-APPLICATION");
		 
		 Mockito.verifyNoMoreInteractions(etlsSpy, cisSpy,sisSpy);
	}

	@Test
	public void verifyDelegatePassthroughCreation2() throws Exception {
		ArgumentCaptor<EventType> eventTypeCapture = ArgumentCaptor.forClass(EventType.class);
		ArgumentCaptor<String> logNameCapture = ArgumentCaptor.forClass(String.class);
		 PowerMockito.whenNew(EventTypeLogSupplier.class).withArguments(eventTypeCapture.capture()).thenReturn(etlsSpy);
		 PowerMockito.whenNew(ClientInfoSupplier.class).withNoArguments().thenReturn(cisSpy);
		 PowerMockito.whenNew(ServerInfoSupplier.class).withArguments(logNameCapture.capture()).thenReturn(sisSpy);

		 LogPrefixAppender lpa = new LogPrefixAppender(false,false,false ,null);
		 String result = lpa.appendTo( testName.getMethodName()+"-LOGGER", Logger.EVENT_UNSPECIFIED,  testName.getMethodName()+"-MESSAGE");
		 
		 //Based on the forced returns in the before block
		 Assert.assertEquals("[EVENT_TYPE CLIENT_INFO -> SERVER_INFO] "+ testName.getMethodName()+"-MESSAGE", result);
	     
		 Assert.assertEquals(Logger.EVENT_UNSPECIFIED, eventTypeCapture.getValue());
		 Assert.assertEquals(testName.getMethodName()+"-LOGGER",logNameCapture.getValue());
		 
		 Mockito.verify(etlsSpy, Mockito.times(1)).get();
		 Mockito.verify(cisSpy, Mockito.times(1)).get();
		 Mockito.verify(sisSpy, Mockito.times(1)).get();
		 
		 Mockito.verify(cisSpy, Mockito.times(1)).setLogUserInfo(false);
		 Mockito.verify(sisSpy, Mockito.times(1)).setLogServerIp(false);
		 Mockito.verify(sisSpy, Mockito.times(1)).setLogApplicationName(false, null);
		 
		 Mockito.verifyNoMoreInteractions(etlsSpy, cisSpy,sisSpy);
	}

}
