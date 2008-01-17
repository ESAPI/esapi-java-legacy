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
package org.owasp.esapi.interfaces;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * The ILogger interface defines a set of methods that can be used to log
 * security events. Implementors should use a well established logging library
 * as it is quite difficult to create a high-performance logger.
 * <P>
 * <img src="doc-files/Logger.jpg" height="600">
 * <P>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface ILogger {

	// FIXME: ENHANCE Is this type approach right? Should it be configurable somehow?

	/** The SECURITY. */
	String SECURITY = "SECURITY";

	/** The USABILITY. */
	String USABILITY = "USABILITY";

	/** The PERFORMANCE. */
	String PERFORMANCE = "PERFORMANCE";

    /**
     * Format the Source IP address, URL, URL parameters, and all form
     * parameters into a string for the log file. The list of parameters to
     * obfuscate should be specified in order to prevent sensitive informatiton
     * from being logged. If a null list is provided, then all parameters will
     * be logged.
     * 
     * @param type the type
     * @param request the request
     * @param sensitiveParams the sensitive params
     */
    public void logHTTPRequest(String type, HttpServletRequest request, List parameterNamesToObfuscate);


	/**
     * Log critical.
     * 
     * @param type the type
     * @param message the message
     */
	void logCritical(String type, String message);
	
	/**
     * Log critical.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logCritical(String type, String message, Throwable throwable);

	/**
     * Log debug.
     * 
     * @param type the type
     * @param message the message
     */
	void logDebug(String type, String message);
	
	/**
     * Log debug.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logDebug(String type, String message, Throwable throwable);

	/**
     * Log error.
     * 
     * @param type the type
     * @param message the message
     */
	void logError(String type, String message);
	
	/**
     * Log error.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logError(String type, String message, Throwable throwable);

	/**
     * Log success.
     * 
     * @param type the type
     * @param message the message
     */
	void logSuccess(String type, String message);
	
	/**
     * Log success.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logSuccess(String type, String message, Throwable throwable);

	/**
     * Log trace.
     * 
     * @param type the type
     * @param message the message
     */
	void logTrace(String type, String message);
	
	/**
     * Log trace.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logTrace(String type, String message, Throwable throwable);

	/**
     * Log warning.
     * 
     * @param type the type
     * @param message the message
     */
	void logWarning(String type, String message);
	
	/**
     * Log warning.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void logWarning(String type, String message, Throwable throwable);
}
