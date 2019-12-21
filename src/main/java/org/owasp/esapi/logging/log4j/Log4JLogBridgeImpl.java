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

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;

/**
 * Implementation which is intended to bridge the ESAPI Logging API into LOG4J supported Object structures.
 *
 */
@Deprecated
public class Log4JLogBridgeImpl implements Log4JLogBridge {
    /** Configuration providing associations between esapi log levels and LOG4J levels.*/
    private final Map<Integer,Log4JLogLevelHandler> esapiSlfLevelMap;
    /** Cleaner used for log content.*/
    private final LogScrubber scrubber;
    /** Appender used for assembling default message content for all logs.*/
    private final LogAppender appender;

    /**
     * Constructor.
     * @param logScrubber  Log message cleaner.
     * @param esapiSlfHandlerMap Map identifying ESAPI -> LOG4J log level associations.
     */
    public Log4JLogBridgeImpl(LogAppender messageAppender, LogScrubber logScrubber, Map<Integer, Log4JLogLevelHandler> esapiSlfHandlerMap) {
        //Defensive copy to prevent external mutations.
        this.esapiSlfLevelMap = new HashMap<>(esapiSlfHandlerMap);
        this.scrubber = logScrubber;
        this.appender = messageAppender;
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message) {
        Log4JLogLevelHandler handler = esapiSlfLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup LOG4J level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
            String fullMessage = appender.appendTo(logger.getName(), type, message);
            String cleanString = scrubber.cleanMessage(fullMessage);

            handler.log(logger, cleanString);
        }
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) {
        Log4JLogLevelHandler handler = esapiSlfLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup LOG4J level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
            String fullMessage = appender.appendTo(logger.getName(), type, message);
            String cleanString = scrubber.cleanMessage(fullMessage);

            handler.log(logger, cleanString, throwable);
        }
    }
}
