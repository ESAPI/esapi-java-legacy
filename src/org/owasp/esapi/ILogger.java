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


/**
 * The ILogger interface defines a set of methods that can be used to log
 * security events. Implementors should use a well established logging library
 * as it is quite difficult to create a high-performance logger.
 * <P>
 * <img src="doc-files/Logger.jpg" height="600">
 * <P>
 * 
 * The order of logging levels is:
 * <ul>
 * <li>trace</li>
 * <li>debug</li>
 * <li>info</li>
 * <li>warn</li>
 * <li>error</li>
 * <li>fatal (the most serious)</li>
 * </ul>
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
     * Log critical.
     * 
     * @param type the type
     * @param message the message
     */
	void fatal(String type, String message);
	
	/**
     * Log critical.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void fatal(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isFatalEnabled();

	/**
     * Log debug.
     * 
     * @param type the type
     * @param message the message
     */
	void debug(String type, String message);
	
	/**
     * Log debug.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void debug(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isDebugEnabled();

	/**
     * Log error.
     * 
     * @param type the type
     * @param message the message
     */
	void error(String type, String message);
	
	/**
     * Log error.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void error(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isErrorEnabled();

	/**
     * Log success.
     * 
     * @param type the type
     * @param message the message
     */
	void info(String type, String message);
	
	/**
     * Log success.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void info(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isInfoEnabled();

	/**
     * Log trace.
     * 
     * @param type the type
     * @param message the message
     */
	void trace(String type, String message);
	
	/**
     * Log trace.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void trace(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isTraceEnabled();

	/**
     * Log warning.
     * 
     * @param type the type
     * @param message the message
     */
	void warning(String type, String message);
	
	/**
     * Log warning.
     * 
     * @param type the type
     * @param message the message
     * @param throwable the throwable
     */
	void warning(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if messages will be output to the log
	 */
	boolean isWarningEnabled();

}
