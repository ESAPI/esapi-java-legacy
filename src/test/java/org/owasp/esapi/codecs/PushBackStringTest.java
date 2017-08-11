package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class PushBackStringTest {

	@Test
	public void testPushbackString() {
		PushbackSequence<Character> pbs = new PushbackString("012345");
		
		pbs.mark();
		assertEquals(0, pbs.index());
		Character first = pbs.next();
		
		System.out.println("0x" + Integer.toHexString(first));
		
		assertEquals("0", new StringBuilder().appendCodePoint(first).toString());
	}
	
	@Test
	public void testPushbackSequence() {
		AbstractPushbackSequence<Integer> pbs = new PushBackSequenceImpl("&#49;2345");
		
		pbs.mark();
		assertEquals(0, pbs.index());
		Integer first = pbs.next();
		
		System.out.println("0x" + Integer.toHexString(first));
		
		assertEquals("&", new StringBuilder().appendCodePoint(first).toString());
		
		Integer second = pbs.next();
		
		if(second == '#'){
			System.out.printf("[%d]:[%d]\n", second, (int) '#');
			
		}
	}
}
