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

package org.owasp.esapi.logging.java;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.owasp.esapi.Logger.EventType;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;

/**
 * Implementation which is intended to bridge the ESAPI Logging API into Java supported Object structures.
 *
 */
public class JavaLogBridgeImpl implements JavaLogBridge {
    /** Configuration providing associations between esapi log levels and Java levels.*/
    private final Map<Integer,JavaLogLevelHandler> esapiJavaLevelMap;
    /** Cleaner used for log content.*/
    private final LogScrubber scrubber;
    /** Appender used for assembling default message content for all logs.*/
    private final LogAppender appender;
    
    /**
     * Constructor.
     * @param logScrubber  Log message cleaner.
     * @param esapiJavaHandlerMap Map identifying ESAPI -> Java log level associations.
     */
    public JavaLogBridgeImpl(LogAppender messageAppender, LogScrubber logScrubber, Map<Integer, JavaLogLevelHandler> esapiJavaHandlerMap) {
        //Defensive copy to prevent external mutations.
        this.esapiJavaLevelMap = new HashMap<>(esapiJavaHandlerMap);
        this.scrubber = logScrubber;
        this.appender = messageAppender;
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message) {
        JavaLogLevelHandler handler = esapiJavaLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup Java level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
        	String fullMessage = appender.appendTo(logger.getName(), type, message);
            String cleanString = scrubber.cleanMessage(fullMessage);
            
            handler.log(logger, cleanString);
        }
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) {
        JavaLogLevelHandler handler = esapiJavaLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup Java level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
        	String fullMessage = appender.appendTo(logger.getName(), type, message);
            String cleanString = scrubber.cleanMessage(fullMessage);

            handler.log(logger, cleanString, throwable);
        }
    }
}
