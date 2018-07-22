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

import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

public class Slf4JLogFactory implements LogFactory {
    private static final char BACKSLASH = '\\';
    private static final char OPEN_SLF_FORMAT='{';
    private static final char CLOSE_SLF_FORMAT='}';
    private static final char[] IMMUNE_SLF4J_HTML = {',', '.', '-', '_', ' ',BACKSLASH, OPEN_SLF_FORMAT, CLOSE_SLF_FORMAT };
    private static final HTMLEntityCodec HTML_CODEC = new HTMLEntityCodec();
    private static final LogScrubber SLF4J_LOG_SCRUBBER = new CodecLogScrubber(HTML_CODEC, IMMUNE_SLF4J_HTML);
    private static Slf4JLogBridge LOG_BRIDGE;
    static {
        Map<Integer, Level> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, Level.TRACE);
        levelLookup.put(Logger.TRACE, Level.TRACE);
        levelLookup.put(Logger.DEBUG, Level.TRACE);
        levelLookup.put(Logger.INFO, Level.TRACE);
        levelLookup.put(Logger.ERROR, Level.TRACE);
        levelLookup.put(Logger.WARNING, Level.TRACE);
        levelLookup.put(Logger.FATAL, Level.TRACE);
        //LEVEL.OFF not used.  If it's off why would we try to log it?
        
        LOG_BRIDGE = new Slf4JLogBridge(SLF4J_LOG_SCRUBBER, levelLookup);
    }
    
    
    @Override
    public Logger getLogger(String moduleName) {
        org.slf4j.Logger slf4JLogger = LoggerFactory.getLogger(moduleName);
        return new Slf4JLogger(slf4JLogger, LOG_BRIDGE, Logger.ALL);
    }

    @Override
    public Logger getLogger(@SuppressWarnings("rawtypes") Class clazz) {
        org.slf4j.Logger slf4JLogger = LoggerFactory.getLogger(clazz);
        return new Slf4JLogger(slf4JLogger, LOG_BRIDGE, Logger.ALL);
    }

}
