package org.owasp.esapi.filters;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
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
}
