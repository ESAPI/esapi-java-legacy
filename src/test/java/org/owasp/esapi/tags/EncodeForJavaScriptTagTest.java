package org.owasp.esapi.tags;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForJavaScriptTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() {
        String input = "Magic String";
        EncodeForJavaScriptTag uit = new EncodeForJavaScriptTag();
        Mockito.when(encoder.encodeForJavaScript(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForJavaScript(input);
        
    }
}
