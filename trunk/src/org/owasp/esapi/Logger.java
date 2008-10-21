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
 * security events. It supports a hierarchy of logging levels which can be configured at runtime to determine
 * the severity of events that are logged, and those below the current threshold that are discarded.
 * Implementors should use a well established logging library
 * as it is quite difficult to create a high-performance logger.
 * <P>
 * <img src="doc-files/Logger.jpg" height="600">
 * <P>
 * 
 * The logging levels defined by this interface (in descending order) are:
 * <ul>
 * <li>fatal (highest value)</li>
 * <li>error</li>
 * <li>warning</li>
 * <li>info</li>
 * <li>debug</li>
 * <li>trace (lowest value)</li>
 * </ul>
 * 
 * This Logger allows callers to determine which logging levels are enabled, and to submit events at different severity levels.
 * Implementors of this interface should:
 * 
 * 1) provide a mechanism for setting the logging level threshold that is currently enabled. This usually works by logging all 
 * events at and above that severity level, and discarding all events below that level.
 * This is usually done via configuration, but can also be made accessible programmatically.
 * 2) ensure that dangerous HTML characters are encoded before they are logged to defend against malicious injection into logs 
 * that might be viewed in an HTML based log viewer.
 * 3) encode any CRLF characters included in log data in order to prevent log injection attacks.
 * 4) avoid logging the user's session ID. Rather, they should log something equivalent like a generated logging session ID, 
 * or a hashed value of the session ID so they can track session specific events without risking the exposure of a live session's ID. 
 * 5) record the following information with each event:
 *   a) identity of the user that caused the event,
 *   b) a description of the event (supplied by the caller),
 *   c) whether the event succeeded or failed (indicated by the caller),
 *   d)	severity level of the event (indicated by the caller),
 *   e) that this is a security relevant event (indicated by the caller),
 *   f) hostname or IP where the event occurred (and ideally the user's source IP as well),
 *   g) a time stamp
 * 
 * Custom logger implementations might also:
 * 6) filter out any sensitive data specific to the current application or organization, such as credit cards, 
 * social security numbers, etc.
 * 
 * In the default implementation, this interface is implemented by JavaLogger.class, which is an inner class in JavaLogFactory.java.
 * JavaLogger.class uses the java.util.logging package as the basis for its logging implementation. This default implementation 
 * implements requirements #1 thru #5 above.
 * 
 * Customization: It is expected that most organizations will implement their own custom Logger class in order to integrate ESAPI
 * logging with their logging infrastructure. The ESAPI Reference Implementation is intended to provide a simple functional example of
 * an implementation.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Logger {

	/**
     * The SECURITY type of log event. 
     */
	public static final EventType SECURITY = new EventType( "SECURITY" );

	/**
     * The USABILITY type of log event. 
     */
	public static final EventType USABILITY = new EventType( "USABILITY" );

	/**
     * The PERFORMANCE type of log event. 
     */
	public static final EventType PERFORMANCE = new EventType( "PERFORMANCE" );
	
	/**
     * The FUNCTIONALITY type of log event. 
     */
	public static final EventType FUNCTIONALITY = new EventType( "FUNCTIONALITY" );

	/**
	 * Defines the type of log event that is being generated. The Logger interface defines 4 types of Log events: 
	 * SECURITY, USABILITY, PERFORMANCE, FUNCTIONALITY. 
     * Your implementation can extend or change this list if desired. The ESAPI reference implementation 
     * generates only SECURITY events.
	 */
	public class EventType {
		
		private String type;
		
		EventType (String name) {
			type = name;
		}
		
		public String toString() {
			return this.type;
		}
	}
	
	/*
     * The Logger interface defines 6 logging levels: FATAL, ERROR, WARNING, INFO, DEBUG, TRACE. It also 
     * supports ALL, which logs all events, and OFF, which disables all logging.
     * Your implementation can extend or change this list if desired. 
     */
	
	/** OFF indicates that no messages should be logged. This level is initialized to Integer.MAX_VALUE. */
	public static final int OFF = Integer.MAX_VALUE;

	/** FATAL indicates that FATAL messages should be logged. This level is initialized to 1000. */
	public static final int FATAL = 1000;

	/** ERROR indicates that ERROR messages and above should be logged. 
	 * This level is initialized to 800. */
    public static final int ERROR = 800;

    /** WARNING indicates that WARNING messages and above should be logged. 
     * This level is initialized to 600. */
    public static final int WARNING = 600;

    /** INFO indicates that INFO messages and above should be logged. 
     * This level is initialized to 400. */
    public static final int INFO = 400;

    /** DEBUG indicates that DEBUG messages and above should be logged. 
     * This level is initialized to 200. */
    public static final int DEBUG = 200;

    /** TRACE indicates that TRACE messages and above should be logged. 
     * This level is initialized to 100. */
    public static final int TRACE = 100;

    /** ALL indicates that all messages should be logged. This level is initialized to Integer.MIN_VALUE. */
    public static final int ALL = Integer.MIN_VALUE;
    

    /**
     * Dynamically set the logging severity level. All events of this level and higher will be logged from 
     * this point forward. All events below this level will be discarded.
     */
    public void setLevel(int level);

    
	/**
     * Log a fatal event if 'fatal' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void fatal(EventType type, boolean success, String message);
	
	/**
     * Log a fatal level security event if 'fatal' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void fatal(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if fatal level messages will be output to the log
	 */
	boolean isFatalEnabled();

	/**
     * Log an error level security event if 'error' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void error(EventType type, boolean success, String message);
	
	/**
     * Log an error level security event if 'error' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void error(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if error level messages will be output to the log
	 */
	boolean isErrorEnabled();

	/**
     * Log a warning level security event if 'warning' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void warning(EventType type, boolean success, String message);
	
	/**
     * Log a warning level security event if 'warning' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void warning(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if warning level messages will be output to the log
	 */
	boolean isWarningEnabled();

	/**
     * Log an info level security event if 'info' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void info(EventType type, boolean success, String message);
	
	/**
     * Log an info level security event if 'info' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void info(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if info level messages will be output to the log
	 */
	boolean isInfoEnabled();

	/**
     * Log a debug level security event if 'debug' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void debug(EventType type, boolean success, String message);
	
	/**
     * Log a debug level security event if 'debug' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void debug(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if debug level messages will be output to the log
	 */
	boolean isDebugEnabled();

	/**
     * Log a trace level security event if 'trace' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     */
	void trace(EventType type, boolean success, String message);
	
	/**
     * Log a trace level security event if 'trace' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param success
     * 		False indicates this was a failed event (which is typical of most log messages.
     * 		True indicates this was a successful event.  
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void trace(EventType type, boolean success, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if trace level messages will be output to the log
	 */
	boolean isTraceEnabled();

}
