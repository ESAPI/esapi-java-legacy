package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class HTMLEntityCodecTest {
	Codec<Integer> codec = new HTMLEntityCodec();
	
	@Test
	public void testEntityDecoding(){
		assertEquals("<", codec.decode("&lt;"));
        assertEquals( "<", codec.decode("&LT"));
        assertEquals( "<", codec.decode("&lt;"));
        assertEquals( "<", codec.decode("&LT;"));
	}
}
