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
	
	@Test
	public void test32BitCJK(){
		String s = "𡘾𦴩𥻂";
		String expected = "&#x2163e;&#x26d29;&#x25ec2;";
		String bad = "&#xd845;&#xde3e;&#xd85b;&#xdd29;&#xd857;&#xdec2;";
		assertEquals(false, expected.equals(bad));
		assertEquals(expected, codec.encode(new char[0], s));
	}
}
