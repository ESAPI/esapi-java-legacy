package org.owasp.esapi.tags;

import javax.servlet.jsp.JspTagException;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;

public class EncodeForURLTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() throws Exception {
        String input = "Magic String";
        EncodeForURLTag uit = new EncodeForURLTag();
        Mockito.when(encoder.encodeForURL(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForURL(input);
        
    }
    
    @Test (expected = JspTagException.class)
    public void assertExceptionOnEncodingFalure() throws Exception {
        String input = "Magic String";
        EncodeForURLTag uit = new EncodeForURLTag();
        Mockito.when(encoder.encodeForURL(input)).thenThrow(new EncodingException("Test-Scope", "SAMPLE"));
        uit.encode(input, encoder);
    }
}
