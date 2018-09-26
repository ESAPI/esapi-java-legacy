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
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.slf4j.IMarkerFactory;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.helpers.BasicMarkerFactory;

/**
 * Implementation which is intended to bridge the ESAPI Logging API into SLF4J supported Object structures.
 *
 */
public class Slf4JLogBridgeImpl implements Slf4JLogBridge {
    //BasicMarkerFactory uses ConcurrentHashMap to track data.  This *should be* thread safe.
    private static final IMarkerFactory MARKER_FACTORY = new BasicMarkerFactory();
    /** Configuration providing associations between esapi log levels and SLF4J levels.*/
    private final Map<Integer,Slf4JLogLevelHandler> esapiSlfLevelMap;
    /** Cleaner used for log content.*/
    private final LogScrubber scrubber;
    
    /**
     * Constructor.
     * @param logScrubber  Log message cleaner.
     * @param esapiSlfHandlerMap Map identifying ESAPI -> SLF4J log level associations.
     */
    public Slf4JLogBridgeImpl(LogScrubber logScrubber, Map<Integer, Slf4JLogLevelHandler> esapiSlfHandlerMap) {
        //Defensive copy to prevent external mutations.
        this.esapiSlfLevelMap = new HashMap<>(esapiSlfHandlerMap);
        this.scrubber = logScrubber;
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message) {
        Slf4JLogLevelHandler handler = esapiSlfLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup SLF4J level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
            Marker typeMarker = MARKER_FACTORY.getMarker(type.toString());
            String cleanString = scrubber.cleanMessage(message);
            handler.log(logger, typeMarker, cleanString);
        }
    }
    @Override
    public void log(Logger logger, int esapiLevel, EventType type, String message, Throwable throwable) {
        Slf4JLogLevelHandler handler = esapiSlfLevelMap.get(esapiLevel);
        if (handler == null) {
            throw new IllegalArgumentException("Unable to lookup SLF4J level mapping for esapi value of " + esapiLevel);
        }
        if (handler.isEnabled(logger)) {
            Marker typeMarker = MARKER_FACTORY.getMarker(type.toString());
            String cleanString = scrubber.cleanMessage(message);
            handler.log(logger, typeMarker, cleanString, throwable);
        }
    }
}
