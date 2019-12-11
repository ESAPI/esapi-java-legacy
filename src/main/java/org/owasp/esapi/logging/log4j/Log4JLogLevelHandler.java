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
package org.owasp.esapi.logging.log4j;

import org.apache.log4j.Logger;

/**
 * Contract used to isolate translations for each SLF4J Logging Level.
 * 
 * @see Log4JLogLevelHandlers
 * @see Log4JLogBridgeImpl
 *
 */
 interface Log4JLogLevelHandler {
     /** Check if the logging level is enabled for the specified logger.*/
    boolean isEnabled(Logger logger);
    /**
     * Calls the appropriate log level event on the specified logger.
     * @param logger Logger to invoke.
     * @param msg Message to log.
     */
    void log(Logger logger, String msg);
    /**
     * Calls the appropriate log level event on the specified logger.
     * @param logger Logger to invoke
     * @param msg Message to log
     * @param th Throwable to log.
     */
    void log(Logger logger, String msg, Throwable th);
}
