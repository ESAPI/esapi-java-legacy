package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class PercentCodecTest {
	
	@Test
	public void testPercentDecode(){
		Codec codec = new PercentCodec();
		
		String expected = " ";
		assertEquals(expected, codec.decode("%20"));
	}
}
