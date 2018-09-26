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

/**
 * LogScrubber implementation which replaces newline and carriage return values.
 *
 */
public class NewlineLogScrubber implements LogScrubber {
    /** Newline */
    private static final char NEWLINE = '\n';
    /** Carriage Return. */
    private static final char CARRIAGE_RETURN = '\r';
    /** Default Replacement value. */
    private static final char LINE_WRAP_REPLACE = '_';

    @Override
    public String cleanMessage(String message) {
        return message.replace(NEWLINE, LINE_WRAP_REPLACE).replace(CARRIAGE_RETURN, LINE_WRAP_REPLACE);
    }
}
