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

package org.owasp.esapi.logging.slf4j;

import java.util.HashMap;
import java.util.Map;

import org.owasp.esapi.Logger.EventType;
import org.slf4j.IMarkerFactory;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.BasicMarkerFactory;

/**
 * Implementation which is intended to bridge the ESAPI Logging API into SLF4J supported Object structures.
 *
 */
public class Slf4JLogBridge {
    //BasicMarkerFactory uses ConcurrentHashMap to track data.  This *should be* thread safe.
    private static final IMarkerFactory MARKER_FACTORY = new BasicMarkerFactory();
    private final Map<Integer,Level> esapiSlfLevelMap;
    private final LogScrubber scrubber;
    
    public Slf4JLogBridge(LogScrubber logScrubber, Map<Integer, Level> esapiSlfLevelMap) {
        //Defensive copy to prevent external mutations.
        this.esapiSlfLevelMap = new HashMap<>(esapiSlfLevelMap);
        this.scrubber = logScrubber;
    }
    
    public void log(Logger logger, int esapiLevel, EventType type, String message) {
        Slf4JLogHandler handler = getHandler(esapiLevel);
        if (handler.isEnabled(logger)) {
            Marker typeMarker = MARKER_FACTORY.getMarker(type.toString());
            String cleanString = scrubber.cleanMessage(message);
            handler.log(logger, typeMarker, cleanString);
        }
    }

    public void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) {
        Slf4JLogHandler handler = getHandler(esapiLevel);
        if (handler.isEnabled(logger)) {
            Marker typeMarker = MARKER_FACTORY.getMarker(type.toString());
            String cleanString = scrubber.cleanMessage(message);
            handler.log(logger, typeMarker, cleanString, throwable);
        }
    }
    
   public Slf4JLogHandler getHandler(int esapiLevel) {
        Level slfLevel = esapiSlfLevelMap.get(esapiLevel);
        if (slfLevel == null) {
            throw new IllegalArgumentException("Unable to lookup SLF4J level mapping for esapi value of " + esapiLevel);
        }
        Slf4JLogHandler handler;
        switch (slfLevel) {
        case ERROR:
            handler = Slf4JLogHandler.ERROR;
            break;
        case WARN:
            handler = Slf4JLogHandler.WARN;
            break;
        case INFO:
            handler = Slf4JLogHandler.INFO;
            break;
        case DEBUG:
            handler = Slf4JLogHandler.DEBUG;
            break;
        case TRACE:
            handler = Slf4JLogHandler.TRACE;
            break;
            default:
                throw new IllegalArgumentException("Unable to lookup SLF4J level mapping for esapi value of " + esapiLevel);
        }
        
        return handler;
    }
   
}
