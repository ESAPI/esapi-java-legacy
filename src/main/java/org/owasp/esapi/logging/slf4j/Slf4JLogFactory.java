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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.slf4j.LoggerFactory;

public class Slf4JLogFactory implements LogFactory {
    private static final char BACKSLASH = '\\';
    private static final char OPEN_SLF_FORMAT='{';
    private static final char CLOSE_SLF_FORMAT='}';
    private static final char[] IMMUNE_SLF4J_HTML = {',', '.', '-', '_', ' ',BACKSLASH, OPEN_SLF_FORMAT, CLOSE_SLF_FORMAT };
    private static final HTMLEntityCodec HTML_CODEC = new HTMLEntityCodec();
    private static LogScrubber SLF4J_LOG_SCRUBBER;
    private static Slf4JLogBridge LOG_BRIDGE;
    static {
        
        boolean encodeLog = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_ENCODING_REQUIRED);
        SLF4J_LOG_SCRUBBER = createLogScrubber(encodeLog);
        
        Map<Integer, Slf4JLogHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, Slf4JLogHandlers.TRACE);
        levelLookup.put(Logger.TRACE, Slf4JLogHandlers.TRACE);
        levelLookup.put(Logger.DEBUG, Slf4JLogHandlers.DEBUG);
        levelLookup.put(Logger.INFO, Slf4JLogHandlers.INFO);
        levelLookup.put(Logger.ERROR, Slf4JLogHandlers.ERROR);
        levelLookup.put(Logger.WARNING, Slf4JLogHandlers.WARN);
        levelLookup.put(Logger.FATAL, Slf4JLogHandlers.ERROR);
        //LEVEL.OFF not used.  If it's off why would we try to log it?
        
        LOG_BRIDGE = new Slf4JLogBridgeImpl(SLF4J_LOG_SCRUBBER, levelLookup);
    }
    
    /*package*/ static LogScrubber createLogScrubber(boolean requiresEncoding) {
        List<LogScrubber> messageScrubber = new ArrayList<>();
        messageScrubber.add(new NewlineLogScrubber());
        
        if (requiresEncoding) {
            messageScrubber.add(new CodecLogScrubber(HTML_CODEC, IMMUNE_SLF4J_HTML));
        }
        
        return new CompositeLogScrubber(messageScrubber);
        
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
