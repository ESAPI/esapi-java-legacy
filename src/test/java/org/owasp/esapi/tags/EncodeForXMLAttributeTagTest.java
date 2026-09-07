package org.owasp.esapi.tags;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForXMLAttributeTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() {
        String input = "Magic String";
        EncodeForXMLAttributeTag uit = new EncodeForXMLAttributeTag();
        Mockito.when(encoder.encodeForXMLAttribute(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForXMLAttribute(input);
        
    }
}
