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
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.logging.log4j;

import org.apache.log4j.Priority;
import org.apache.log4j.spi.LoggerFactory;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.logging.appender.LogAppender;
import org.owasp.esapi.logging.cleaning.LogScrubber;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

/**
 * Service Provider Interface implementation that can be provided as the org.apache.log4j.spi.LoggerFactory reference in a Log4J configuration.
 * <br>
 * <code>
 *   &ltloggerFactory class="org.owasp.esapi.logging.log4j.Log4JLoggerFactory"/&gt
 * </code>
 */
@Deprecated
public class Log4JLoggerFactory implements LoggerFactory {
    /** Log appender instance.*/
    private static LogAppender LOG4J_LOG_APPENDER;
    /** Log cleaner instance.*/
    private static LogScrubber LOG4J_LOG_SCRUBBER;

    static {
        boolean encodeLog = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_ENCODING_REQUIRED);
        LOG4J_LOG_SCRUBBER = Log4JLogFactory.createLogScrubber(encodeLog);

        boolean logUserInfo = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_USER_INFO);
        boolean logClientInfo = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_CLIENT_INFO);
        boolean logApplicationName = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_APPLICATION_NAME);
        String appName = ESAPI.securityConfiguration().getStringProp(DefaultSecurityConfiguration.APPLICATION_NAME);
        boolean logServerIp = ESAPI.securityConfiguration().getBooleanProp(DefaultSecurityConfiguration.LOG_SERVER_IP);
        LOG4J_LOG_APPENDER = Log4JLogFactory.createLogAppender(logUserInfo, logClientInfo, logServerIp, logApplicationName, appName);
    }

    /**
     * This constructor must be public so it can be accessed from within log4j
     */
    public Log4JLoggerFactory() {}

    /**
     * Overridden to return instances of org.owasp.esapi.reference.Log4JLogger.
     * 
     * @param name The class name to return a logger for.
     * @return org.owasp.esapi.reference.Log4JLogger
     */
    public org.apache.log4j.Logger makeNewLoggerInstance(String name) {		
        return new EsapiLog4JWrapper(name);
    }


    public static class EsapiLog4JWrapper extends org.apache.log4j.Logger {

        protected EsapiLog4JWrapper(String name) {
            super(name);			
        }

        @Override
        protected void forcedLog(String fqcn, Priority level, Object message, Throwable t) {
            String toClean = message.toString();

            String fullMessage = LOG4J_LOG_APPENDER.appendTo(getName(), null, toClean);
            String cleanMsg = LOG4J_LOG_SCRUBBER.cleanMessage(fullMessage);

            super.forcedLog(fqcn, level, cleanMsg, t);
        }

    }
}
