package org.owasp.esapi.logging.appender;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.owasp.esapi.Authenticator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.User;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ESAPI.class})
@PowerMockIgnore("javax.security.*") //Required since User extends javax.security.Principal
public class ClientInfoSupplierTest {
	private static final String ESAPI_SESSION_ATTR = "ESAPI_SESSION";
	
	@Rule
    public TestName testName = new TestName();
	
	private HttpServletRequest mockRequest;
	private HttpSession mockSession;
	private Authenticator mockAuth;
	private Randomizer mockRand;
	private User mockUser;
	
	@Before
	public void before() throws Exception {
		mockAuth =mock(Authenticator.class); 
		mockRand =mock(Randomizer.class); 
		mockRequest =mock(HttpServletRequest.class);
		mockSession =mock(HttpSession.class);
		mockUser =mock(User.class);
		
		mockStatic(ESAPI.class);
		when(ESAPI.class, "currentRequest").thenReturn(mockRequest);
		when(ESAPI.class, "authenticator").thenReturn(mockAuth);
		when(ESAPI.class, "randomizer").thenReturn(mockRand);
		
		when(mockRequest.getSession(false)).thenReturn(mockSession);
		when(mockSession.getAttribute(ESAPI_SESSION_ATTR)).thenReturn(testName.getMethodName()+ "-SESSION");
		
		//Session value generation
		when(mockRand.getRandomInteger(ArgumentMatchers.anyInt(), ArgumentMatchers.anyInt())).thenReturn(55555);
		 
		when(mockUser.getAccountName()).thenReturn(testName.getMethodName() + "-USER");
		when(mockUser.getLastHostAddress()).thenReturn(testName.getMethodName() + "-HOST_ADDR");
		
	     
	    when(mockAuth.getCurrentUser()).thenReturn(mockUser);
	}
	
	@Test
	public void testHappyPath() throws Exception {
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		assertEquals(testName.getMethodName() + "-USER:"+ testName.getMethodName() + "-SESSION@"+testName.getMethodName() + "-HOST_ADDR", result);
		
		verify(mockAuth,times(1)).getCurrentUser();
		verify(mockRequest,times(1)).getSession(false);
		verify(mockSession,times(1)).getAttribute(ESAPI_SESSION_ATTR);
		verify(mockUser,times(1)).getAccountName();
		verify(mockUser,times(1)).getLastHostAddress();
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
	
	@Test
	public void testLogUserOff() {
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(false);
		String result = cis.get();
		
		assertTrue(result.isEmpty());
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
	
	@Test
	public void testLogUserNull() {
		when(mockAuth.getCurrentUser()).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		assertEquals("#ANONYMOUS#:"+testName.getMethodName()+ "-SESSION@", result);
		
		verify(mockAuth,times(1)).getCurrentUser();
		verify(mockRequest,times(1)).getSession(false);
		verify(mockSession,times(1)).getAttribute(ESAPI_SESSION_ATTR);
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
	
	@Test
	public void testNullRequest() throws Exception {
		when(ESAPI.class, "currentRequest").thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when request is null		
		assertEquals(testName.getMethodName() + "-USER:@"+testName.getMethodName() + "-HOST_ADDR", result);
		
		verify(mockAuth,times(1)).getCurrentUser();
		verify(mockUser,times(1)).getAccountName();
		verify(mockUser,times(1)).getLastHostAddress();
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
	
	@Test
	public void testNullSession() throws Exception {
		when(mockRequest.getSession(false)).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when session is null		
		assertEquals(testName.getMethodName() + "-USER:@"+testName.getMethodName() + "-HOST_ADDR", result);
		
		
		verify(mockAuth,times(1)).getCurrentUser();
		verify(mockRequest,times(1)).getSession(false);
		verify(mockUser,times(1)).getAccountName();
		verify(mockUser,times(1)).getLastHostAddress();
		
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
	
	
	
	@Test
	public void testNullEsapiSession() throws Exception {
		when(mockSession.getAttribute(ESAPI_SESSION_ATTR)).thenReturn(null);
		ClientInfoSupplier cis = new ClientInfoSupplier();
		cis.setLogUserInfo(true);
		String result = cis.get();
		
		//sid is empty when session is null		
		assertEquals(testName.getMethodName() + "-USER:55555@"+testName.getMethodName() + "-HOST_ADDR", result);
		
		verify(mockAuth,times(1)).getCurrentUser();
		verify(mockRequest,times(1)).getSession(false);
		verify(mockSession,times(1)).getAttribute(ESAPI_SESSION_ATTR);
		verify(mockSession, times(1)).setAttribute(ESAPI_SESSION_ATTR, (""+55555));
		verify(mockRand, times(1)).getRandomInteger(ArgumentMatchers.anyInt(), ArgumentMatchers.anyInt());
		verify(mockUser,times(1)).getAccountName();
		verify(mockUser,times(1)).getLastHostAddress();
		
		verifyNoMoreInteractions(mockAuth, mockRand, mockRequest, mockSession, mockUser);
	}
}