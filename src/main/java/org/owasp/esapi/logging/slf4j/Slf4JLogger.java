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

import org.owasp.esapi.Logger;

public class Slf4JLogger implements org.owasp.esapi.Logger {
    private final org.slf4j.Logger delegate;
    private final Slf4JLogBridge logBridge;
    private int esapiLogLevel;
    
    public Slf4JLogger(org.slf4j.Logger slf4JLogger, Slf4JLogBridge bridge, int defaultEsapiLevel) {
        delegate = slf4JLogger;
        this.logBridge = bridge;
        esapiLogLevel = defaultEsapiLevel;
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
        return esapiLogLevel < esapiLevel;
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
        return esapiLogLevel;
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
       esapiLogLevel = level;
    }
    
}
