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
import org.owasp.esapi.PropNames;
import org.owasp.esapi.codecs.HTMLEntityCodec;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.appender.LogPrefixAppender;
import org.owasp.esapi.logging.cleaning.CodecLogScrubber;
import org.owasp.esapi.logging.cleaning.CompositeLogScrubber;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.logging.cleaning.NewlineLogScrubber;

import static org.owasp.esapi.PropNames.LOG_ENCODING_REQUIRED;
import static org.owasp.esapi.PropNames.LOG_USER_INFO;
import static org.owasp.esapi.PropNames.LOG_CLIENT_INFO;
import static org.owasp.esapi.PropNames.LOG_APPLICATION_NAME;
import static org.owasp.esapi.PropNames.APPLICATION_NAME;
import static org.owasp.esapi.PropNames.LOG_SERVER_IP;

/**
 * LogFactory implementation which creates JAVA supporting Loggers.
 * <br><br>
 * Options for customizing this configuration (in recommended order)
 * <ol>
 * <li>Consider using the <i>SLF4JLogFactory</i> with a java-logging implementation.</li>
 * <li>Configure java LogManager system properties as defined by the <i>java.util.logging.LogManager</i> API</li>
 * <li>Overwrite the esapi-java-logging.properties file with the desired logging configurations. <br>A default file implementation is available in the configuration jar on GitHub under the 'Releases'</li>
 * <li>Specifically set the system property for LogManager in the custom-code solution to prevent ESAPI JavaLogFactory from overriding project configuration</li>
 * <li>Create a custom JavaLogFactory class in client project baseline and update the ESAPI.properties configuration to use that reference.</li>
 * </ol>
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
        boolean encodeLog = ESAPI.securityConfiguration().getBooleanProp(LOG_ENCODING_REQUIRED);
        JAVA_LOG_SCRUBBER = createLogScrubber(encodeLog);


        boolean logUserInfo = ESAPI.securityConfiguration().getBooleanProp(LOG_USER_INFO);
        boolean logClientInfo = ESAPI.securityConfiguration().getBooleanProp(LOG_CLIENT_INFO);
        boolean logApplicationName = ESAPI.securityConfiguration().getBooleanProp(LOG_APPLICATION_NAME);
        String appName = ESAPI.securityConfiguration().getStringProp(APPLICATION_NAME);
        boolean logServerIp = ESAPI.securityConfiguration().getBooleanProp(LOG_SERVER_IP);
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
        if (System.getProperties().keySet().stream().anyMatch(propKey ->
        "java.util.logging.config.class".equals(propKey) || "java.util.logging.config.file".equals(propKey))) {
            // LogManager has external configuration.  Do not load ESAPI defaults.
            // See javadoc for the LogManager class for more information on properties.
            boolean isStartupSysoutDisabled = Boolean.valueOf(System.getProperty(PropNames.DISCARD_LOGSPECIAL, Boolean.FALSE.toString()));
            if (!isStartupSysoutDisabled) {
                String logManagerPreferredMsg = String.format("[ESAPI-STARTUP] ESAPI JavaLogFactory Configuration will not be applied. "
                        + "java.util.LogManager configuration Detected. "
                        + "{\"java.util.logging.config.class\":\"%s\",\"java.util.logging.config.file\":\"%s\"}",
                        System.getProperty("java.util.logging.config.class"), System.getProperty("java.util.logging.config.file"));

                System.out.println(logManagerPreferredMsg);
                // ::SAMPLE OUTPUT::
                //[ESAPI-STARTUP] ESAPI JavaLogFactory Configuration will not be applied.  java.util.LogManager configuration Detected.{"java.util.logging.config.class":"some.defined.value","java.util.logging.config.file":"null"}
            }

            return;
        }
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
