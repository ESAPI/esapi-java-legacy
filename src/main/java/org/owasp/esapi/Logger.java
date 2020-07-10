/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007-2019 - The OWASP Foundation
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
 * The logging levels defined by this interface (in descending order) are:
 * <ul>
 * <li>fatal (highest value)</li>
 * <li>error</li>
 * <li>warning</li>
 * <li>info</li>
 * <li>debug</li>
 * <li>trace (lowest value)</li>
 * </ul>
 * There are also several variations of {@code always()} methods that will <i>always</i>
 * log a message regardless of the log level.
 * <p>
 * ESAPI also allows for the definition of the type of log event that is being generated.
 * The Logger interface predefines 6 types of Log events:
 * <ul>
 * <li>SECURITY_SUCCESS</li>
 * <li>SECURITY_FAILURE</li>
 * <li>SECURITY_AUDIT</li>
 * <li>EVENT_SUCCESS</li>
 * <li>EVENT_FAILURE</li>
 * <li>EVENT_UNSPECIFIED</li>
 * </ul>
 * <p>
 * Your implementation can extend or change this list if desired. 
 * <p>
 * This Logger allows callers to determine which logging levels are enabled, and to submit events 
 * at different severity levels.<br>
 * <br>Implementors of this interface should:
 * 
 * <ol>
 * <li>provide a mechanism for setting the logging level threshold that is currently enabled. This usually works by logging all 
 * events at and above that severity level, and discarding all events below that level.
 * This is usually done via configuration, but can also be made accessible programmatically.</li>
 * <li>ensure that dangerous HTML characters are encoded before they are logged to defend against malicious injection into logs 
 * that might be viewed in an HTML based log viewer.</li>
 * <li>encode any CRLF characters included in log data in order to prevent log injection attacks.</li>
 * <li>avoid logging the user's session ID. Rather, they should log something equivalent like a 
 * generated logging session ID, or a hashed value of the session ID so they can track session specific 
 * events without risking the exposure of a live session's ID.</li> 
 * <li>record the following information with each event:</li>
 *   <ol type="a">
 *   <li>identity of the user that caused the event,</li>
 *   <li>a description of the event (supplied by the caller),</li>
 *   <li>whether the event succeeded or failed (indicated by the caller),</li>
 *   <li>severity level of the event (indicated by the caller),</li>
 *   <li>that this is a security relevant event (indicated by the caller),</li>
 *   <li>hostname or IP where the event occurred (and ideally the user's source IP as well),</li>
 *   <li>a time stamp</li>
 *   </ol>
 * </ol>
 *  
 * Custom logger implementations might also:
 * <ol start="6">
 * <li>filter out any sensitive data specific to the current application or organization, such as credit cards, 
 * social security numbers, etc.</li>
 * </ol>
 * 
 * There are both Log4j and native Java Logging default implementations. JavaLogger uses the java.util.logging package as the basis for its logging 
 * implementation. Both default implementations implements requirements #1 thru #5 above.<br>
 * <br>
 * Customization: It is expected that most organizations will implement their own custom Logger class in 
 * order to integrate ESAPI logging with their logging infrastructure. The ESAPI Reference Implementation 
 * is intended to provide a simple functional example of an implementation.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Logger {

	// All implied static final as this is an interface
	
	/**
     * A security type of log event that has succeeded. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	EventType SECURITY_SUCCESS = new EventType( "SECURITY SUCCESS", true);

	/**
     * A security type of log event that has failed. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	EventType SECURITY_FAILURE = new EventType( "SECURITY FAILURE", false);

	/**
	 * A security type of log event that is associated with an audit trail of some type,
	 * but the log event is not specifically something that has either succeeded or failed
	 * or that is irrelevant in the case of this logged message.
	 */
	// CHECKME: Should the Boolean for this be 'null' or 'true'? See EVENT_UNSPECIFIED.
	EventType SECURITY_AUDIT = new EventType( "SECURITY AUDIT", null);

	/**
     * A non-security type of log event that has succeeded. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	EventType EVENT_SUCCESS = new EventType( "EVENT SUCCESS", true);
	
	/**
     * A non-security type of log event that has failed. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	EventType EVENT_FAILURE = new EventType( "EVENT FAILURE", false);

	/**
     * A non-security type of log event that is unspecified. This is one of 6 predefined
     * ESAPI logging events. New events can be added.
     */
	EventType EVENT_UNSPECIFIED = new EventType( "EVENT UNSPECIFIED", null);

	/**
	 * Defines the type of log event that is being generated. The Logger interface defines 6 types of Log events:
	 * SECURITY_SUCCESS, SECURITY_FAILURE, EVENT_SUCCESS, EVENT_FAILURE, EVENT_UNSPECIFIED.
     * Your implementation can extend or change this list if desired. 
	 */
	class EventType {
		
		private String type;
		private Boolean success = null;
		
		public EventType (String name, Boolean newSuccess) {
			this.type = name;
			this.success = newSuccess;
		}
		
		public Boolean isSuccess() {
			return success;
		}
		
        /**
         * Convert the {@code EventType} to a string.
         * @return The event type name.
         */
		@Override
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
	int OFF = Integer.MAX_VALUE;

	/** FATAL indicates that only FATAL messages should be logged. This level is initialized to 1000. */
	int FATAL = 1000;

	/** ERROR indicates that ERROR messages and above should be logged. 
	 * This level is initialized to 800. */
    int ERROR = 800;

    /** WARNING indicates that WARNING messages and above should be logged. 
     * This level is initialized to 600. */
    int WARNING = 600;

    /** INFO indicates that INFO messages and above should be logged. 
     * This level is initialized to 400. */
    int INFO = 400;

    /** DEBUG indicates that DEBUG messages and above should be logged. 
     * This level is initialized to 200. */
    int DEBUG = 200;

    /** TRACE indicates that TRACE messages and above should be logged. 
     * This level is initialized to 100. */
    int TRACE = 100;

    /** ALL indicates that all messages should be logged. This level is initialized to Integer.MIN_VALUE. */
    int ALL = Integer.MIN_VALUE;
    

    /**
     * Dynamically set the ESAPI logging severity level. All events of this level and higher will be logged from 
     * this point forward for all logs. All events below this level will be discarded.
     * 
     * @param level The level to set the logging level to. 
     */
    void setLevel(int level);
    
    /** Retrieve the current ESAPI logging level for this logger. See
     * {@link org.owasp.esapi.logging.log4j.Log4JLogger} for an explanation of
     * why this method is not simply called {@code getLevel()}.
     * 
     * @return The current logging level.
     */
    int getESAPILevel();
    
	/**
     * Log a fatal event if 'fatal' level logging is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void fatal(EventType type, String message);
	
	/**
     * Log a fatal level security event if 'fatal' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void fatal(EventType type, String message, Throwable throwable);

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
     * @param message 
     * 		the message to log
     */
	void error(EventType type, String message);
	
	/**
     * Log an error level security event if 'error' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void error(EventType type, String message, Throwable throwable);

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
     * @param message 
     * 		the message to log
     */
	void warning(EventType type, String message);
	
	/**
     * Log a warning level security event if 'warning' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void warning(EventType type, String message, Throwable throwable);

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
     * @param message 
     * 		the message to log
     */
	void info(EventType type, String message);
	
	/**
     * Log an info level security event if 'info' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void info(EventType type, String message, Throwable throwable);

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
     * @param message 
     * 		the message to log
     */
	void debug(EventType type, String message);
	
	/**
     * Log a debug level security event if 'debug' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void debug(EventType type, String message, Throwable throwable);

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
     * @param message 
     * 		the message to log
     */
	void trace(EventType type, String message);
	
	/**
     * Log a trace level security event if 'trace' level logging is enabled 
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void trace(EventType type, String message, Throwable throwable);

	/**
	 * Allows the caller to determine if messages logged at this level
	 * will be discarded, to avoid performing expensive processing.
	 * 
	 * @return true if trace level messages will be output to the log
	 */
	boolean isTraceEnabled();

	/**
     * Log an event regardless of what logging level is enabled.
     * 
     * @param type 
     * 		the type of event
     * @param message 
     * 		the message to log
     */
	void always(EventType type, String message);
	
	/**
     * Log an event regardless of what logging level is enabled
     * and also record the stack trace associated with the event.
     * 
     * @param type 
     * 		the type of event 
     * @param message 
     * 		the message to log
     * @param throwable 
     * 		the exception to be logged
     */
	void always(EventType type, String message, Throwable throwable);
}
