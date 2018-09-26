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

import static org.junit.Assert.assertEquals;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.owasp.esapi.codecs.Codec;

public class CodecLogScrubberTest {
    @Rule
    public ExpectedException exEx = ExpectedException.none();

    @Test
    public void testNullCodecThrowsException() {
        exEx.expect(IllegalArgumentException.class);
        exEx.expectMessage("cannot be null");

        new CodecLogScrubber(null, new char[0]);
    }

    @Test
    public void testNullImmuneIsEmpty() {
        String message = "cleanThis";
        @SuppressWarnings("unchecked")
        Codec<String> mockCodec = Mockito.mock(Codec.class);

        CodecLogScrubber scrubber = new CodecLogScrubber(mockCodec, null);

        ArgumentCaptor<char[]> immuneCapture = ArgumentCaptor.forClass(char[].class);

        scrubber.cleanMessage(message);

        Mockito.verify(mockCodec, Mockito.times(1)).encode(immuneCapture.capture(), ArgumentMatchers.matches(message));
        Mockito.verifyNoMoreInteractions(mockCodec);

        assertEquals(0, immuneCapture.getValue().length);
    }

    @Test
    public void testCleanMessage() {
        char[] immune = new char[] { 'a', 'b', 'c' };
        String message = "cleanThis";
        @SuppressWarnings("unchecked")
        Codec<String> mockCodec = Mockito.mock(Codec.class);

        CodecLogScrubber scrubber = new CodecLogScrubber(mockCodec, immune);

        scrubber.cleanMessage(message);

        Mockito.verify(mockCodec, Mockito.times(1)).encode(ArgumentMatchers.same(immune), ArgumentMatchers.matches(message));
        Mockito.verifyNoMoreInteractions(mockCodec);

    }

}
