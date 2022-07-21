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
 * @created 2019
 */

package org.owasp.esapi.logging.appender;

import org.owasp.esapi.Logger.EventType;

/**
 * Contract interface for appending content to a log message.
 *
 */
public interface LogAppender {

    /**
     * Creates a replacement Log Message and returns it to the caller.
     * @param logName name of the logger.
     * @param eventType EventType of the log event being processed.
     * @param message The original message.
     * @return Updated replacement message.
     */
    public String appendTo(String logName, EventType eventType, String message);

}
