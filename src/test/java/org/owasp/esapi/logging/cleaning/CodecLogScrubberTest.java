package org.owasp.esapi.logging.cleaning;

import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.Codec;

public class CodecLogScrubberTest {

    @Test
    public void testCleanMessage() {
        char[] immune = new char[] {'a','b','c'};
        String message = "cleanThis";
        Codec<String> mockCodec = Mockito.mock(Codec.class);
        
        CodecLogScrubber scrubber = new CodecLogScrubber(mockCodec, immune);
        
        scrubber.cleanMessage(message);
        
        Mockito.verify(mockCodec, Mockito.times(1)).encode(Matchers.same(immune), Matchers.matches(message));
        Mockito.verifyNoMoreInteractions(mockCodec);
        
    }
}
