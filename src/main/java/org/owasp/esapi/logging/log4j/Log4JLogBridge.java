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
package org.owasp.esapi.logging.log4j;

import org.apache.log4j.Logger;
import org.owasp.esapi.Logger.EventType;
/**
 * Contract for translating an ESAPI log event into an Log4J log event.
 * 
 */
@Deprecated
public interface Log4JLogBridge {
    /**
     * Translation for the provided ESAPI level, type, and message to the specified Log4J Logger.
     * @param logger Logger to receive the translated message.
     * @param esapiLevel ESAPI level of event.
     * @param type ESAPI event type
     * @param message ESAPI event message content.
     */
    void log(Logger logger, int esapiLevel, EventType type, String message) ;
    /**
     * Translation for the provided ESAPI level, type, message, and Throwable to the specified Log4J Logger.
     * @param logger Logger to receive the translated message.
     * @param esapiLevel ESAPI level of event.
     * @param type ESAPI event type
     * @param message ESAPI event message content.
     * @param throwable ESAPI event Throwable content
     */
    void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) ;

}
