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

import org.owasp.esapi.codecs.Codec;

/**
 * Implementation of a LogScrubber which passes strings through a delegate codec
 * with specific character immunity sets.
 *
 */
public class CodecLogScrubber implements LogScrubber {
    /** Codec implementation used to scrub messages. */
    private final Codec<?> customizedMessageCodec;
    /**
     * Set of characters which will not be altered by the codec for this scrubber.
     */
    private final char[] immuneMessageChars;

    /**
     * Ctr.
     * 
     * @param messageCodec
     *            Delegate codec. Cannot be {@code null}
     * @param immuneChars
     *            Immune character set.
     */
    public CodecLogScrubber(Codec<?> messageCodec, char[] immuneChars) {
        if (messageCodec == null) {
            throw new IllegalArgumentException("Codec reference cannot be null");
        }
        this.customizedMessageCodec = messageCodec;
        this.immuneMessageChars = immuneChars == null ? new char[0] : immuneChars;
    }

    @Override
    public String cleanMessage(String message) {
        return customizedMessageCodec.encode(immuneMessageChars, message);
    }
}
