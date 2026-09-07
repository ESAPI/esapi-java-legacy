package org.owasp.esapi.tags;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.UnsupportedEncodingException;

import javax.servlet.jsp.JspTagException;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForBase64TagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() throws Exception {
        String input = "Magic String";
        EncodeForBase64Tag uit = new EncodeForBase64Tag();
        Mockito.when(encoder.encodeForBase64(input.getBytes("UTF-8"), false)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForBase64(input.getBytes("UTF-8"), false);
        
    }
    
    @Test
    public void testSettersGetters() {
        EncodeForBase64Tag uit = new EncodeForBase64Tag();
        assertEquals("UTF-8", uit.getEncoding());
        assertFalse(uit.getWrap());
        
        uit.setWrap(true);
        uit.setEncoding("ASCII");
        
        assertEquals("ASCII", uit.getEncoding());
        assertTrue(uit.getWrap());
    }
    
    @Test (expected = JspTagException.class)
    public void assertExceptionOnEncodingFalure() throws Exception {
        String input = "Magic String";
        EncodeForBase64Tag uit = new EncodeForBase64Tag();
        Mockito.when(encoder.encodeForBase64(input.getBytes("UTF-8"), false)).thenAnswer(i -> { throw new UnsupportedEncodingException();});
        uit.encode(input, encoder);
    }
}
