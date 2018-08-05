/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @created 2018
 */
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
