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

import org.owasp.esapi.Logger;
/**
 * ESAPI Logger implementation which relays events to an Java delegate.
 */
public class JavaLogger implements org.owasp.esapi.Logger {
    /** Delegate Logger.*/
    private final java.util.logging.Logger delegate;
    /** Handler for translating events from ESAPI context for Java processing.*/
    private final JavaLogBridge logBridge;
    /** Maximum log level that will be forwarded to Java from the ESAPI context.*/
    private int maxLogLevel;

    /**
     * Constructs a new instance. 
     * @param JavaLogger Delegate Java logger.
     * @param bridge Translator for ESAPI -> Java logging events.
     * @param defaultEsapiLevel Maximum ESAPI log level events to propagate.
     */
    public JavaLogger(java.util.logging.Logger JavaLogger, JavaLogBridge bridge, int defaultEsapiLevel) {
        delegate = JavaLogger;
        this.logBridge = bridge;
        maxLogLevel = defaultEsapiLevel;
    }

    private void log(int esapiLevel, EventType type, String message) {
        if (isEnabled(esapiLevel)) {
            logBridge.log(delegate, esapiLevel, type, message);
        }
    }

    private void log(int esapiLevel, EventType type, String message, Throwable throwable) {
        if (isEnabled(esapiLevel)) {
            logBridge.log(delegate, esapiLevel, type, message, throwable);
        }
    }


    private boolean isEnabled(int esapiLevel) {
        //Are Logger.OFF and Logger.ALL reversed?  This should be simply the less than or equal to check...
        return (esapiLevel <= maxLogLevel && maxLogLevel != Logger.OFF) || maxLogLevel == Logger.ALL;
    }

    @Override
    public void always(EventType type, String message) {
        log (Logger.ALL, type, message);
    }

    @Override
    public void always(EventType type, String message, Throwable throwable) {
        log (Logger.ALL, type, message, throwable);
    }

    @Override
    public void trace(EventType type, String message) {
        log (Logger.TRACE, type, message);
    }

    @Override
    public void trace(EventType type, String message, Throwable throwable) {
        log (Logger.TRACE, type, message, throwable);
    }

    @Override
    public void debug(EventType type, String message) {
        log (Logger.DEBUG, type, message);
    }

    @Override
    public void debug(EventType type, String message, Throwable throwable) {
        log (Logger.DEBUG, type, message, throwable);
    }

    @Override
    public void info(EventType type, String message) {
        log (Logger.INFO, type, message);
    }

    @Override
    public void info(EventType type, String message, Throwable throwable) {
        log (Logger.INFO, type, message, throwable);
    }

    @Override
    public void warning(EventType type, String message) {
        log (Logger.WARNING, type, message);
    }

    @Override
    public void warning(EventType type, String message, Throwable throwable) {
        log (Logger.WARNING, type, message, throwable);
    }

    @Override
    public void error(EventType type, String message) {
        log (Logger.ERROR, type, message);
    }

    @Override
    public void error(EventType type, String message, Throwable throwable) {
        log (Logger.ERROR, type, message, throwable);   
    }

    @Override
    public void fatal(EventType type, String message) {
        log (Logger.FATAL, type, message);
    }

    @Override
    public void fatal(EventType type, String message, Throwable throwable) {
        log (Logger.FATAL, type, message, throwable);
    }

    @Override
    public int getESAPILevel() {
        return maxLogLevel;
    }

    @Override
    public boolean isTraceEnabled() {
        return isEnabled(Logger.TRACE);
    }

    @Override
    public boolean isDebugEnabled() {
        return isEnabled(Logger.DEBUG);
    }
    @Override
    public boolean isInfoEnabled() {
        return isEnabled(Logger.INFO); 
    }
    @Override
    public boolean isWarningEnabled() {
        return isEnabled(Logger.WARNING);
    }

    @Override
    public boolean isErrorEnabled() {
        return isEnabled(Logger.ERROR);
    }

    @Override
    public boolean isFatalEnabled() {
        return isEnabled(Logger.FATAL);
    }


    @Override
    public void setLevel(int level) {
        maxLogLevel = level;
    }

}
