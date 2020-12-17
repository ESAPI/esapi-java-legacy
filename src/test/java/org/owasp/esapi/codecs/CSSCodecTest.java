package org.owasp.esapi.codecs;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class CSSCodecTest {
	private static final char[] IMMUNE_STUB = new char[0];
	/** Unit In Test*/
	private CSSCodec uit = new CSSCodec();
	
	@Test
    public void testCSSTripletLeadString() {
    	assertEquals("rgb(255,255,255)\\21 ", uit.encode(IMMUNE_STUB, "rgb(255,255,255)!"));
    	assertEquals("rgb(25%,25%,25%)\\21 ", uit.encode(IMMUNE_STUB, "rgb(25%,25%,25%)!"));
    }
	@Test
    public void testCSSTripletTailString() {
    	assertEquals("\\24 field\\3d rgb(255,255,255)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(255,255,255)!"));
    	assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(25%,25%,25%)!"));
    }
	@Test
    public void testCSSTripletStringPart() {
    	assertEquals("\\24 field\\3d rgb(255,255,255)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(255,255,255)!"));
    	assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(25%,25%,25%)!"));
    }
	@Test
    public void testCSSTripletStringMultiPart() {
    	assertEquals("\\24 field\\3d rgb(255,255,255)\\21 \\20 \\24 field\\3d rgb(255,255,255)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(255,255,255)! $field=rgb(255,255,255)!"));
    	assertEquals("\\24 field\\3d rgb(25%,25%,25%)\\21 \\20 \\24 field\\3d rgb(25%,25%,25%)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(25%,25%,25%)! $field=rgb(25%,25%,25%)!"));
    	assertEquals("\\24 field\\3d rgb(255,255,255)\\21 \\20 \\24 field\\3d rgb(25%,25%,25%)\\21 ", uit.encode(IMMUNE_STUB, "$field=rgb(255,255,255)! $field=rgb(25%,25%,25%)!"));
    }
}
