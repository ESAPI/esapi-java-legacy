package org.owasp.esapi.tags;

import org.junit.Test;
import org.mockito.Mockito;
import org.owasp.esapi.Encoder;

public class EncodeForVBScriptTagTest {

    
    Encoder encoder = Mockito.spy(Encoder.class);
    
    
    @Test
    public void assertEncoderInvocation() {
        String input = "Magic String";
        EncodeForVBScriptTag uit = new EncodeForVBScriptTag();
        Mockito.when(encoder.encodeForVBScript(input)).thenReturn("unused");
        
        uit.encode(input, encoder);
        Mockito.verify(encoder, Mockito.times(1)).encodeForVBScript(input);
        
    }
}
