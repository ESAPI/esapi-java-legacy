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

import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;

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
     * Hide the constructor.
     * 
     * @param applicationName the application name
     * @param moduleName the module name
     * @param jlogger the jlogger
     */
    private Logger(String applicationName, String moduleName, java.util.logging.Logger jlogger) {
        this.applicationName = applicationName;
        this.moduleName = moduleName;
        this.jlogger = jlogger;
        // FIXME: AAA this causes some weird classloading problem, since SecurityConfiguration logs.
        // jlogger.setLevel(SecurityConfiguration.getInstance().getLogLevel());
        this.jlogger.setLevel( Level.ALL );
    }

    /**
     * Formats an HTTP request into a log suitable string. This implementation logs the remote host IP address (or
     * hostname if available), the request method (GET/POST), the URL, and all the querystring and form parameters. All
     * the paramaters are presented as though they were in the URL even if they were in a form. Any parameters that
     * match items in the parameterNamesToObfuscate are shown as eight asterisks.
     * 
     * @see org.owasp.esapi.interfaces.ILogger#formatHttpRequestForLog(javax.servlet.http.HttpServletRequest)
     */
    public void logHTTPRequest(String type, HttpServletRequest request, List parameterNamesToObfuscate) {
        StringBuffer params = new StringBuffer();
        Iterator i = request.getParameterMap().keySet().iterator();
        while (i.hasNext()) {
            String key = (String) i.next();
            String[] value = (String[]) request.getParameterMap().get(key);
            for (int j = 0; j < value.length; j++) {
                params.append(key + "=");
                if (parameterNamesToObfuscate.contains(key)) {
                    params.append("********");
                } else {
                    params.append(value[j]);
                }
                if (j < value.length - 1) {
                    params.append("&");
                }
            }
            if (i.hasNext())
                params.append("&");
        }
        String msg = request.getMethod() + " " + request.getRequestURL() + (params.length() > 0 ? "?" + params : "");
        logSuccess(type, msg);
    }

    /**
     * Gets the logger.
     * 
     * @param applicationName the application name
     * @param moduleName the module name
     * @return the logger
     */
    public static Logger getLogger(String applicationName, String moduleName) {
        java.util.logging.Logger jlogger = java.util.logging.Logger.getLogger(applicationName + ":" + moduleName);
        return new Logger(applicationName, moduleName, jlogger);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logTrace(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void logTrace(String type, String message, Throwable throwable) {
        log(Level.WARNING, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logTrace(java.lang.String, java.lang.String)
     */
    public void logTrace(String type, String message) {
        log(Level.WARNING, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logDebug(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void logDebug(String type, String message, Throwable throwable) {
        log(Level.CONFIG, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logDebug(java.lang.String, java.lang.String)
     */
    public void logDebug(String type, String message) {
        log(Level.CONFIG, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logError(short, java.lang.String, java.lang.String, java.lang.Throwable)
     */
    public void logError(String type, String message, Throwable throwable) {
        log(Level.WARNING, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logError(java.lang.String, java.lang.String)
     */
    public void logError(String type, String message) {
        log(Level.WARNING, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void logSuccess(String type, String message) {
        log(Level.INFO, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logSuccess(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void logSuccess(String type, String message, Throwable throwable) {
        log(Level.INFO, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logWarning(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void logWarning(String type, String message, Throwable throwable) {
        log(Level.WARNING, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logWarning(java.lang.String, java.lang.String)
     */
    public void logWarning(String type, String message) {
        log(Level.WARNING, type, message, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logCritical(short, java.lang.String, java.lang.String,
     * java.lang.Throwable)
     */
    public void logCritical(String type, String message, Throwable throwable) {
        log(Level.SEVERE, type, message, throwable);
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.ILogger#logCritical(java.lang.String, java.lang.String)
     */
    public void logCritical(String type, String message) {
        log(Level.SEVERE, type, message, null);
    }

    /**
     * Log the message after encoding any special characters that might inject into an HTML based log viewer.
     * 
     * @param message the message
     * @param level the level
     * @param type the type
     * @param throwable the throwable
     */
    private void log(Level level, String type, String message, Throwable throwable) {
        User user = Authenticator.getInstance().getCurrentUser();
        
        String clean = message;
        if ( SecurityConfiguration.getInstance().getLogEncodingRequired() ) {
        	clean = Encoder.getInstance().encodeForHTML(message);
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
        // String clean = Encoder.getInstance().encodeForHTML(message);
        // if (!message.equals(clean)) {
        //     clean += "(Encoded)";
        // }
        String msg = "SECURITY" + ": " + "esapi" + "/" + "none" + " -- " + message;
        jlogger.logp(Level.WARNING, applicationName, moduleName, msg, throwable);
    }

}
