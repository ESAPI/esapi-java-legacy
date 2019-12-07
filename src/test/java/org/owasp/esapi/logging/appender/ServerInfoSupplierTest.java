package org.owasp.esapi.logging.appender;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.owasp.esapi.ESAPI;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ESAPI.class})
public class ServerInfoSupplierTest {
	@Rule
    public TestName testName = new TestName();
	
	private HttpServletRequest request;
	@Before
	public void buildStaticMocks() throws Exception {
		request = Mockito.mock(HttpServletRequest.class);
		 PowerMockito.mockStatic(ESAPI.class);
	     PowerMockito.when(ESAPI.class, "currentRequest").thenReturn(request);
	}
	
	@Test
	public void verifyFullOutput() {
		Mockito.when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
		Mockito.when(request.getLocalPort()).thenReturn(99999);
		
		ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
		sis.setLogApplicationName(true, testName.getMethodName()+"-APPLICATION");
		sis.setLogServerIp(true);
		
		String result = sis.get();
		org.junit.Assert.assertEquals("LOCAL_ADDR:99999/"+testName.getMethodName()+"-APPLICATION/"+testName.getMethodName(), result);
	}
	
	@Test
	public void verifyOutputNullRequest() throws Exception {
		  PowerMockito.when(ESAPI.class, "currentRequest").thenReturn(null);
		ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
		sis.setLogApplicationName(true, testName.getMethodName()+"-APPLICATION");
		sis.setLogServerIp(true);
		
		String result = sis.get();
		org.junit.Assert.assertEquals("/"+testName.getMethodName()+"-APPLICATION/"+testName.getMethodName(), result);
	}
	
	@Test
	public void verifyOutputNoAppName() {
		Mockito.when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
		Mockito.when(request.getLocalPort()).thenReturn(99999);
		
		ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
		sis.setLogApplicationName(false, null);
		sis.setLogServerIp(true);
		
		String result = sis.get();
		org.junit.Assert.assertEquals("LOCAL_ADDR:99999/"+testName.getMethodName(), result);
	}
	
	@Test
	public void verifyOutputNullAppName() {
		Mockito.when(request.getLocalAddr()).thenReturn("LOCAL_ADDR");
		Mockito.when(request.getLocalPort()).thenReturn(99999);
		
		ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
		sis.setLogApplicationName(true, null);
		sis.setLogServerIp(true);
		
		String result = sis.get();
		org.junit.Assert.assertEquals("LOCAL_ADDR:99999/null/"+testName.getMethodName(), result);
	}
	@Test
	public void verifyOutputNoServerIp() {
		ServerInfoSupplier sis = new ServerInfoSupplier(testName.getMethodName());
		sis.setLogApplicationName(true, testName.getMethodName()+"-APPLICATION");
		sis.setLogServerIp(false);
		
		String result = sis.get();
		org.junit.Assert.assertEquals("/"+testName.getMethodName()+"-APPLICATION/"+testName.getMethodName(), result);
	}
	
}
