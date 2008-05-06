/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.util.logging.Level;

import javax.servlet.http.Cookie;
/**
 * Reference implementation of the ILogger interface. This implementation uses the Java logging package, and marks each
 * log message with the currently logged in user and the word "SECURITY" for security related events.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.ILogger
 */
public class Logger implements org.owasp.esapi.interfaces.ILogger {

    // FIXME: ENHANCE somehow make configurable so that successes and failures are logged according to a configuration.

    /** The jlogger. */
    private java.util.logging.Logger jlogger = null;

    /** The application name. */
    private String applicationName = null;

    /** The module name. */
    private String moduleName = null;
    
    /**
     * Public constructor should only ever be called via the appropriate LogFactory
     * 
     * @param applicationName the application name
     * @param moduleName the module name
     */
    public Logger(String applicationName, String moduleName) {
        this.applicationName = applicationName;
        this.moduleName = moduleName;
        this.jlogger = java.util.logging.Logger.getLogger(applicationName + ":" + moduleName);
        // FIXME: AAA this causes some weird classloading problem, since SecurityConfiguration logs.
        // jlogger.setLevel(ESAPI.securityConfiguration().getLogLevel());
        this.jlogger.setLevel( Level.ALL );
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logTrace(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void trace(String type, String message, Throwable throwable) {
        log(Level.FINEST, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logTrace(java.lang.String, java.lang.String)
     */
    public void trace(String type, String message) {
        log(Level.FINEST, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logDebug(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void debug(String type, String message, Throwable throwable) {
        log(Level.FINE, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logDebug(java.lang.String, java.lang.String)
     */
    public void debug(String type, String message) {
        log(Level.FINE, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logError(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void error(String type, String message, Throwable throwable) {
        log(Level.SEVERE, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logError(java.lang.String, java.lang.String)
     */
    public void error(String type, String message) {
        log(Level.SEVERE, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void info(String type, String message) {
        log(Level.INFO, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void info(String type, String message, Throwable throwable) {
        log(Level.INFO, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logWarning(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void warning(String type, String message, Throwable throwable) {
        log(Level.WARNING, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logWarning(java.lang.String, java.lang.String)
     */
    public void warning(String type, String message) {
        log(Level.WARNING, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logCritical(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void fatal(String type, String message, Throwable throwable) {
        log(Level.SEVERE, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logCritical(java.lang.String, java.lang.String)
     */
    public void fatal(String type, String message) {
        log(Level.SEVERE, type, message, null);
    }

    /**
     * Log the message after optionally encoding any special characters that might inject into an HTML based log viewer.
     * 
     * @param message the message
     * @param level the level
     * @param type the type
     * @param throwable the throwable
     */
    private void log(Level level, String type, String message, Throwable throwable) {
    	
    	// FIXME: Enhance - consider noting an intrusion detection event on long logs (DOS protection)
    	
        User user = ESAPI.authenticator().getCurrentUser();
        
        // ensure there's something to log
        if ( message == null ) {
        	message = "";
        }
        
        // ensure no CRLF injection into logs for forging records
        String clean = message.replace( '\n', '_' ).replace( '\r', '_' );
        if ( ((SecurityConfiguration)ESAPI.securityConfiguration()).getLogEncodingRequired() ) {
        	clean = ESAPI.encoder().encodeForHTML(message);
            if (!message.equals(clean)) {
                clean += " (Encoded)";
            }
        }
        if ( throwable != null ) {
        	String fqn = throwable.getClass().getName();
        	int index = fqn.lastIndexOf('.');
        	if ( index > 0 ) fqn = fqn.substring(index + 1);
        	StackTraceElement ste = throwable.getStackTrace()[0];
        	clean += "\n    " + fqn + " @ " + ste.getClassName() + "." + ste.getMethodName() + "(" + ste.getFileName() + ":" + ste.getLineNumber() + ")";
        }
        String msg = "";
        if ( user != null ) {
        	msg = type + ": " + user.getAccountName() + "/" + user.getLastHostAddress() + " -- " + clean;
        }
        
        // FIXME: AAA need to configure Java logger not to show throwables
        // jlogger.logp(level, applicationName, moduleName, msg, throwable);
        jlogger.logp(level, applicationName, moduleName, msg);
    }

    /**
     * This special method doesn't include the current user's identity, and is only used during system initialization to
     * prevent loops with the Authenticator.
     * 
     * @param level
     * @param message
     * @param throwable
     */
    // FIXME: this needs to go - note potential log injection problem
    public void logSpecial(String message, Throwable throwable) {
        // String clean = ESAPI.encoder().encodeForHTML(message);
        // if (!message.equals(clean)) {
        //     clean += "(Encoded)";
        // }
        String msg = "SECURITY" + ": " + "esapi" + "/" + "none" + " -- " + message;
        jlogger.logp(Level.WARNING, applicationName, moduleName, msg, throwable);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isDebugEnabled()
     */
    public boolean isDebugEnabled() {
	    return jlogger.isLoggable(Level.FINE);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isErrorEnabled()
     */
    public boolean isErrorEnabled() {
	    return jlogger.isLoggable(Level.SEVERE);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isFatalEnabled()
     */
    public boolean isFatalEnabled() {
	    return jlogger.isLoggable(Level.SEVERE);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isInfoEnabled()
     */
    public boolean isInfoEnabled() {
	    return jlogger.isLoggable(Level.INFO);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isTraceEnabled()
     */
    public boolean isTraceEnabled() {
	    return jlogger.isLoggable(Level.FINEST);
    }

	/* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ILogger#isWarningEnabled()
     */
    public boolean isWarningEnabled() {
	    return jlogger.isLoggable(Level.WARNING);
    }

}
