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
	public void testSetDateHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		long currentTime = System.currentTimeMillis();
		resp.setDateHeader("Foo", currentTime);
		verify(servResp, times(1)).setDateHeader("Foo", currentTime);
	}
	
	@Test
	public void testSetInvalidDateHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		long currentTime = System.currentTimeMillis();
		resp.setDateHeader("<scr", currentTime);
		verify(servResp, times(0)).setDateHeader("<scr", currentTime);
	}
	
	@Test
	public void testSetHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.setHeader("foo", "bar");
		verify(servResp, times(1)).setHeader("foo", "bar");
	}
	
	@Test
	public void testSetInvalidHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.setHeader("foo", "<script>alert</script>");
		verify(servResp, times(0)).setHeader("foo", "<script>alert</script>");
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
	public void testAddIntHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.addIntHeader("aaaa", 4);
		verify(servResp, times(1)).addIntHeader("aaaa", 4);
	}
	
	@Test
	public void testAddInvalidIntHeader(){
		HttpServletResponse servResp = mock(HttpServletResponse.class);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp.addIntHeader(TestUtils.generateStringOfLength(257), Integer.MIN_VALUE);
		verify(servResp, times(0)).addIntHeader(TestUtils.generateStringOfLength(257), Integer.MIN_VALUE);
	}
	
	@Test
	public void testContainsHeader(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		resp = spy(resp);
		resp.addIntHeader("aaaa", Integer.MIN_VALUE);
		verify(servResp, times(1)).addIntHeader("aaaa", Integer.MIN_VALUE);
		assertEquals(true, servResp.containsHeader("aaaa"));
	}
	
	@Test
	public void testAddValidCookie(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
		cookie.setMaxAge(5000);
		Mockito.doCallRealMethod().when(spyResp).addCookie(cookie);
		spyResp.addCookie(cookie);
		
		/*
		 * We're indirectly testing our class.  Since it ultimately
		 * delegates to HttpServletResponse.addHeader, we're actually 
		 * validating that our test method constructs a header with the
		 * expected properties.  This implicitly tests the 
		 * createCookieHeader method as well.
		 */
		verify(servResp, times(1)).addHeader("Set-Cookie", "Foo=aaaaaaaaaa; Max-Age=5000; Secure; HttpOnly");
	}
	
	@Test
	public void testAddValidCookieWithDomain(){
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Cookie cookie = new Cookie("Foo", TestUtils.generateStringOfLength(10));
		cookie.setDomain("evil.com");
		cookie.setMaxAge(-1);
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
	
	@Test
	public void testSendError() throws Exception{
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Mockito.doCallRealMethod().when(spyResp).sendError(200);
		spyResp.sendError(200);
		
		verify(servResp, times(1)).sendError(200, "HTTP error code: 200");;
	}
	
	@Test
	public void testSendStatus() throws Exception{
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Mockito.doCallRealMethod().when(spyResp).setStatus(200);;
		spyResp.setStatus(200);
		
		verify(servResp, times(1)).setStatus(200);;
	}
	
	@Test
	public void testSendStatusWithString() throws Exception{
		HttpServletResponse servResp = new MockHttpServletResponse();
		servResp = spy(servResp);
		SecurityWrapperResponse resp = new SecurityWrapperResponse(servResp);
		SecurityWrapperResponse spyResp = spy(resp);
		Mockito.doCallRealMethod().when(spyResp).setStatus(200, "foo");;
		spyResp.setStatus(200, "foo");
		
		verify(servResp, times(1)).sendError(200, "foo");;
	}
}
