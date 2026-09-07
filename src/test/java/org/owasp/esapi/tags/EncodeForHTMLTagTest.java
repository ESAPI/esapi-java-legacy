package org.owasp.esapi.tags;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForHTMLTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() {
        String input = "Magic String";
        EncodeForHTMLTag uit = new EncodeForHTMLTag();
        Mockito.when(encoder.encodeForHTML(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForHTML(input);
        
    }
}
