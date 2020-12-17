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
package org.owasp.esapi.logging.java;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.LogManager;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.LogFactory;
import org.owasp.esapi.Logger;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.appender.LogPrefixAppender;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
/**
 * LogFactory implementation which creates JAVA supporting Loggers.
 * 
 * This implementation requires that a file named 'esapi-java-logging.properties' exists on the classpath.
 * <br>
 * A default file implementation is available in the configuration jar on GitHub under the 'Releases'
 *
 */
public class JavaLogFactory implements LogFactory {
    /** Immune characters for the codec log scrubber for JAVA context.*/
    private static final char[] IMMUNE_JAVA_HTML = {',', '.', '-', '_', ' ' };
    /** Codec being used to clean messages for logging.*/
    private static final HTMLEntityCodec HTML_CODEC = new HTMLEntityCodec();
    /** Log appender instance.*/
    private static LogAppender JAVA_LOG_APPENDER;
    /** Log cleaner instance.*/
    private static LogScrubber JAVA_LOG_SCRUBBER;
    /** Bridge class for mapping esapi -> java log levels.*/
    private static JavaLogBridge LOG_BRIDGE;

    static {
        boolean encodeLog = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_ENCODING_REQUIRED);
        JAVA_LOG_SCRUBBER = createLogScrubber(encodeLog);


        boolean logUserInfo = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_USER_INFO);
        boolean logClientInfo = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_CLIENT_INFO);
        boolean logApplicationName = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_APPLICATION_NAME);
        String appName = ESAPI.securityConfiguration().getStringProp(DefaultSecurityConfiguration.APPLICATION_NAME);
        boolean logServerIp = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_SERVER_IP);
        JAVA_LOG_APPENDER = createLogAppender(logUserInfo, logClientInfo, logServerIp, logApplicationName, appName);

        Map<Integer, JavaLogLevelHandler> levelLookup = new HashMap<>();
        levelLookup.put(Logger.ALL, JavaLogLevelHandlers.ALWAYS);
        levelLookup.put(Logger.TRACE, JavaLogLevelHandlers.FINEST);
        levelLookup.put(Logger.DEBUG, JavaLogLevelHandlers.FINE);
        levelLookup.put(Logger.INFO, JavaLogLevelHandlers.INFO);
        levelLookup.put(Logger.ERROR, JavaLogLevelHandlers.ERROR);
        levelLookup.put(Logger.WARNING, JavaLogLevelHandlers.WARNING);
        levelLookup.put(Logger.FATAL, JavaLogLevelHandlers.SEVERE);
        //LEVEL.OFF not used.  If it's off why would we try to log it?

        LOG_BRIDGE = new JavaLogBridgeImpl(JAVA_LOG_APPENDER, JAVA_LOG_SCRUBBER, levelLookup);

        readLoggerConfiguration(LogManager.getLogManager());
    }

    /**
     * Attempts to load the expected property file path into the provided LogManager reference.
     * @param logManager LogManager which is being configured.
     */
    /*package*/ static void readLoggerConfiguration(LogManager logManager) {
        /*
         * This will load the logging properties file to control the format of the output for Java logs.
         */
        try (InputStream stream = JavaLogFactory.class.getClassLoader().
                getResourceAsStream("esapi-java-logging.properties")) {
            if (stream == null) {
                throw new ConfigurationException("Unable to locate resource: esapi-java-logging.properties");
            }
            logManager.readConfiguration(stream);
        } catch (IOException ioe) {
            throw new ConfigurationException("Failed to load esapi-java-logging.properties.", ioe);        	
        }
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
            messageScrubber.add(new CodecLogScrubber(HTML_CODEC, IMMUNE_JAVA_HTML));
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
    /*package*/ static LogAppender createLogAppender(boolean logUserInfo, boolean logClientInfo, boolean logServerIp, boolean logApplicationName, String appName) {
        return new LogPrefixAppender(logUserInfo, logClientInfo, logServerIp, logApplicationName, appName);  
    }


    @Override
    public Logger getLogger(String moduleName) {
        java.util.logging.Logger javaLogger = java.util.logging.Logger.getLogger(moduleName); 
        return new JavaLogger(javaLogger, LOG_BRIDGE, Logger.ALL);
    }

    @Override
    public Logger getLogger(@SuppressWarnings("rawtypes") Class clazz) {
        java.util.logging.Logger javaLogger = java.util.logging.Logger.getLogger(clazz.getName());
        return new JavaLogger(javaLogger, LOG_BRIDGE, Logger.ALL);
    }

}
