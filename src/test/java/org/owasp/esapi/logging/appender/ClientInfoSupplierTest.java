package org.owasp.esapi.logging.appender;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.User;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ESAPI.class})
//https://www.gyanblog.com/gyan/20-linkage-error-loader-constraint-violation-junit-test-case-development-issue/
//Does not correct issue with mocking User class
//@PowerMockIgnore("org.owasp.esapi.User")
@Ignore("Need Help figuring out why I cannot mock org.owasp.esapi.User")
public class ClientInfoSupplierTest {
	private static final String ESAPI_SESSION_ATTR = "ESAPI_SESSION";
	
	@Rule
    public TestName testName = new TestName();
	
	private HttpServletRequest request;
	private HttpSession mockSession;
	private Authenticator mockAuth;
	private Randomizer mockRand;
	private User mockUser;
	
	@Before
	public void before() throws Exception {
		mockAuth = PowerMockito.mock(Authenticator.class); 
		mockRand = PowerMockito.mock(Randomizer.class); 
		PowerMockito.mockStatic(ESAPI.class);
		PowerMockito.when(ESAPI.class, "currentRequest").thenReturn(request);
		PowerMockito.when(ESAPI.class, "authenticator").thenReturn(mockAuth);
		PowerMockito.when(ESAPI.class, "randomizer").thenReturn(mockRand);
		
		request = PowerMockito.mock(HttpServletRequest.class);
		mockSession = PowerMockito.mock(HttpSession.class);
		PowerMockito.when(request.getSession(ArgumentMatchers.anyBoolean())).thenReturn(mockSession);
		PowerMockito.when(mockSession.getAttribute(ESAPI_SESSION_ATTR)).thenReturn(testName.getMethodName()+ "-SESSION");
		
		//FIXME:  I cannot mock this interface.
		mockUser = PowerMockito.mock(User.class);
		
		//Session value generation
		PowerMockito.when(mockRand.getRandomInteger(ArgumentMatchers.anyInt(), ArgumentMatchers.anyInt())).thenReturn(55555);
		 
		Mockito.when(mockUser.getAccountName()).thenReturn(testName.getMethodName() + "-USER");
		Mockito.when(mockUser.getLastHostAddress()).thenReturn(testName.getMethodName() + "-HOST_ADDR");
		
	     
	    Mockito.when(mockAuth.getCurrentUser()).thenReturn(mockUser);
	}
	
	@Test
	public void testHappyPath() throws Exception {
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		org.junit.Assert.assertEquals(testName.getMethodName() + "-USER:"+ testName.getMethodName() + "-SESSION@"+testName.getMethodName() + "-HOST_ADDR", result);
	}
	
	@Test
	public void testLogUserOff() {
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(false);
		String result = cis.get();
		
		org.junit.Assert.assertTrue(result.isEmpty());
	}
	
	@Test
	public void testLogUserNull() {
		Mockito.when(mockAuth.getCurrentUser()).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		org.junit.Assert.assertTrue(result.isEmpty());
	}
	
	@Test
	public void testNullRequest() throws Exception {
		PowerMockito.when(ESAPI.class, "currentRequest").thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when request is null		
		org.junit.Assert.assertEquals(testName.getMethodName() + "-USER:@"+testName.getMethodName() + "-HOST_ADDR", result);
	}
	
	@Test
	public void testNullSession() throws Exception {
		PowerMockito.when(request.getSession()).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when session is null		
		org.junit.Assert.assertEquals(testName.getMethodName() + "-USER:@"+testName.getMethodName() + "-HOST_ADDR", result);
	}
	
	
	
	@Test
	public void testNullEsapiSession() throws Exception {
		PowerMockito.when(mockSession.getAttribute(ESAPI_SESSION_ATTR)).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when session is null		
		org.junit.Assert.assertEquals(testName.getMethodName() + "-USER:55555@"+testName.getMethodName() + "-HOST_ADDR", result);
		Mockito.verify(mockSession, Mockito.times(1)).setAttribute(ESAPI_SESSION_ATTR, (""+55555));
	}
}