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
package org.owasp.esapi;


/**
 * The Logger interface defines a set of methods that can be used to log
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
 * In the default implementation, this interface is implemented by JavaLogger.class, which is an inner class in JavaLogFactory.java
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Logger {

	String SECURITY = "SECURITY";
	String USABILITY = "USABILITY";
	String PERFORMANCE = "PERFORMANCE";
	String FUNCTIONALITY = "FUNCTIONALITY";

	/**
     * Log critical.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log to log
     */
	void fatal(String type, String message);
	
	/**
     * Log critical.
     * 
     * @param type 
     * 		the type of event of event
     * @param message 
     * 		the message to log to log
     * @param throwable 
     * 		the exception thrown
     */
	void fatal(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if fatal messages will be output to the log
	 */
	boolean isFatalEnabled();

	/**
     * Log debug.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void debug(String type, String message);
	
	/**
     * Log debug.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception thrown
     */
	void debug(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if debug messages will be output to the log
	 */
	boolean isDebugEnabled();

	/**
     * Log error.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void error(String type, String message);
	
	/**
     * Log error.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception thrown
     */
	void error(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if error messages will be output to the log
	 */
	boolean isErrorEnabled();

	/**
     * Log success.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void info(String type, String message);
	
	/**
     * Log success.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception thrown
     */
	void info(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true info if messages will be output to the log
	 */
	boolean isInfoEnabled();

	/**
     * Log trace.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void trace(String type, String message);
	
	/**
     * Log trace.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception thrown
     */
	void trace(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if trace messages will be output to the log
	 */
	boolean isTraceEnabled();

	/**
     * Log warning.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void warning(String type, String message);
	
	/**
     * Log warning.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception thrown
     */
	void warning(String type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing
	 * 
	 * @return true if warning messages will be output to the log
	 */
	boolean isWarningEnabled();

}
