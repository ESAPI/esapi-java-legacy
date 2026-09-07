package org.owasp.esapi.tags;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForHTMLAttributeTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() {
        String input = "Magic String";
        EncodeForHTMLAttributeTag uit = new EncodeForHTMLAttributeTag();
        Mockito.when(encoder.encodeForHTMLAttribute(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForHTMLAttribute(input);
        
    }
}
