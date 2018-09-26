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
 * Contract interface for cleaning log message output.
 *
 */
public interface LogScrubber {

    /**
     * Updates the given message to account for restrictions for this implementation
     * and returns the result.
     * 
     * @param message
     *            Original message to clean.
     * @return Cleaned message.
     */
    public String cleanMessage(String message);

}
