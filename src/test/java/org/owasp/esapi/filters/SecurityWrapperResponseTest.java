package org.owasp.esapi.filters;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Collection;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.owasp.esapi.http.MockHttpServletResponse;
import org.owasp.esapi.util.TestUtils;
import org.powermock.modules.junit4.PowerMockRunner;

//@PrepareForTest({SecurityWrapperResponse.class})
@RunWith(PowerMockRunner.class)
public class SecurityWrapperResponseTest {
	
	@Test
	public void testAddHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.addHeader("Foo", "bar");
		verify(servResp, times(1)).addHeader("Foo", "bar");
	}
	
	@Test
	public void testAddDateHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		long currentTime = System.currentTimeMillis();
		resp.addDateHeader("Foo", currentTime);
		verify(servResp, times(1)).addDateHeader("Foo", currentTime);
	}
	
	@Test
	public void testInvalidDateHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		long currentTime = System.currentTimeMillis();
		resp.addDateHeader("Foo\\r\\n", currentTime);
		verify(servResp, times(0)).addDateHeader("Foo", currentTime);
	}
	
	@Test
	public void testAddHeaderInvalidValueLength(){
		//refactor this to use a spy. 
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Mockito.doCallRealMethod().when(spyResp).addHeader("Foo", TestUtils.generateStringOfLength(4097));
		resp.addHeader("Foo", TestUtils.generateStringOfLength(4097));
		verify(servResp, times(0)).addHeader("Foo", "bar");
	}
	
	@Test
	public void testAddHeaderInvalidKeyLength(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.addHeader(TestUtils.generateStringOfLength(257), "bar");
		verify(servResp, times(0)).addHeader("Foo", "bar");
	}
	
	@Test
	public void testAddValidCookie(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
		Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
		spyResp.addCookie(cookie);
		/*
		 * We're indirectly testing our class.  Since it ultimately
		 * delegates to HttpServletResponse.addHeader, we're actually 
		 * validating that our test method constructs a header with the
		 * expected properties.  This implicitly tests the 
		 * createCookieHeader method as well.
		 */
		verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Secure; HttpOnly");
	}
	
	@Test
	public void testAddValidCookieWithDomain(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
		cookie.setDomain("evil.com");
		Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
		spyResp.addCookie(cookie);
		verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Domain=evil.com; Secure; HttpOnly");
	}
	
	@Test
	public void testAddValidCookieWithPath(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
		cookie.setDomain("evil.com");
		cookie.setPath("/foo/bar");
		Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
		spyResp.addCookie(cookie);
		verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Domain=evil.com; Path=/foo/bar; Secure; HttpOnly");
	}
	
	@Test
	public void testAddInValidCookie(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(5000));
		Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
		
		spyResp.addCookie(cookie);
		verify(servResp, times(0)).addHeader("Set-Cookie", "Foo=" + TestUtils.generateStringOfLength(5000) + "; Secure; HttpOnly");
	}
}
