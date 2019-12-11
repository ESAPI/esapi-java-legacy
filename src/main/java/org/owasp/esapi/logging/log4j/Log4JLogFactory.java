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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.LogManager;
import org.apache.log4j.PropertyConfigurator;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.appender.LogPrefixAppender;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.owasp.esapi.logging.java.JavaLogFactory;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
/**
 * LogFactory implementation which creates Log4J supporting Loggers.
 *
 */
public class Log4JLogFactory implements LogFactory {
	 /** Immune characters for the codec log scrubber for JAVA context.*/
    private static final char[] IMMUNE_LOG4J_HTML = {',', '.', '-', '_', ' ' };
    /** Codec being used to clean messages for logging.*/
    private static final HTMLEntityCodec HTML_CODEC = new HTMLEntityCodec();
    /** Log appender instance.*/
    private static LogAppender Log4J_LOG_APPENDER;
    /** Log cleaner instance.*/
    private static LogScrubber Log4J_LOG_SCRUBBER;
    /** Bridge class for mapping esapi -> log4j log levels.*/
    private static Log4JLogBridge LOG_BRIDGE;
    
    static {
        boolean encodeLog = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_ENCODING_REQUIRED);
        Log4J_LOG_SCRUBBER = createLogScrubber(encodeLog);
        
    	boolean logClientInfo = true;
		boolean logApplicationName = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_APPLICATION_NAME);
		String appName = ESAPI.securityConfiguration().getStringProp(DefaultSecurityConfiguration.APPLICATION_NAME);
		boolean logServerIp = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_SERVER_IP);
        Log4J_LOG_APPENDER = createLogAppender(logClientInfo, logServerIp, logApplicationName, appName);
        
        Map<Integer, Log4JLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, Log4JLogLevelHandlers.TRACE);
        levelLookup.put(Logger.TRACE, Log4JLogLevelHandlers.TRACE);
        levelLookup.put(Logger.DEBUG, Log4JLogLevelHandlers.DEBUG);
        levelLookup.put(Logger.INFO, Log4JLogLevelHandlers.INFO);
        levelLookup.put(Logger.ERROR, Log4JLogLevelHandlers.ERROR);
        levelLookup.put(Logger.WARNING, Log4JLogLevelHandlers.WARN);
        levelLookup.put(Logger.FATAL, Log4JLogLevelHandlers.FATAL);
        //LEVEL.OFF not used.  If it's off why would we try to log it?
        
        LOG_BRIDGE = new Log4JLogBridgeImpl(Log4J_LOG_APPENDER, Log4J_LOG_SCRUBBER, levelLookup);
        
        try (InputStream stream = Log4JLogFactory.class.getClassLoader().
        		getResourceAsStream("log4j.xml")) {
        	PropertyConfigurator.configure(stream);
        } catch (IOException ioe) {
        	System.err.print(new IOException("Failed to load log4j.xml.", ioe));        	
        }
        
        OutputStream nullOutputStream = new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				//No Op
			}
		};
        
       System.setOut(new PrintStream(nullOutputStream));
    }
    
    /**
     * Populates the default log scrubber for use in factory-created loggers.
     * @param requiresEncoding {@code true} if encoding is required for log content.
     * @return LogScrubber instance.
     */
    /*package*/ static LogScrubber createLogScrubber(boolean requiresEncoding) {
        List<LogScrubber> messageScrubber = new ArrayList<>();
        messageScrubber.add(new NewlineLogScrubber());
        
        if (requiresEncoding) {
            messageScrubber.add(new CodecLogScrubber(HTML_CODEC, IMMUNE_LOG4J_HTML));
        }
        
        return new CompositeLogScrubber(messageScrubber);
        
    }
    
    /**
     * Populates the default log appender for use in factory-created loggers.
     * @param appName 
     * @param logApplicationName 
     * @param logServerIp 
     * @param logClientInfo 
     * 
     * @return LogAppender instance.
     */
    /*package*/ static LogAppender createLogAppender(boolean logClientInfo, boolean logServerIp, boolean logApplicationName, String appName) {
       return new LogPrefixAppender(logClientInfo, logServerIp, logApplicationName, appName);       
    }
    
    
    @Override
    public Logger getLogger(String moduleName) {
    	org.apache.log4j.Logger log4JLogger = org.apache.log4j.Logger.getLogger(moduleName);
        return new Log4JLogger(log4JLogger, LOG_BRIDGE, Logger.ALL);
    }

    @Override
    public Logger getLogger(@SuppressWarnings("rawtypes") Class clazz) {
    	org.apache.log4j.Logger log4JLogger = org.apache.log4j.Logger.getLogger(clazz);
        return new Log4JLogger(log4JLogger, LOG_BRIDGE, Logger.ALL);
    }

}
