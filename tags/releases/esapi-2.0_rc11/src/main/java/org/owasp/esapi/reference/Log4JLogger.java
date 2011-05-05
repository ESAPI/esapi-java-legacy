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
package org.owasp.esapi.reference;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.log4j.Category;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggerFactory;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.User;

/**
 * Reference implementation of the Logger interface. This implementation extends org.apache.log4j.Logger
 * in order to take advantage of per-class and per-package configuration options provided by Log4J. 
 *
 * @author August Detlefsen (augustd at codemagi dot com)
 *         <a href="http://www.codemagi.com">CodeMagi, Inc.</a>
 * @since October 15, 2010
 * @see org.owasp.esapi.reference.Log4JLogFactory
 * @see org.owasp.esapi.reference.Log4JLoggerFactory
 */
public class Log4JLogger extends org.apache.log4j.Logger implements org.owasp.esapi.Logger {

	/** The log factory to use in creating new instances. */
	private static LoggerFactory factory = new Log4JLoggerFactory();

	/** The application name using this log */
	private static String applicationName = ESAPI.securityConfiguration().getApplicationName();

	/** Log the application name? */
	private static boolean logAppName = ESAPI.securityConfiguration().getLogApplicationName();
	
	/** Log the server ip? */
	private static boolean logServerIP = ESAPI.securityConfiguration().getLogServerIP();

	public Log4JLogger(String name) {
		super(name);
	}

	/**
	 * This method overrides {@link Logger#getInstance} by supplying
	 * its own factory type as a parameter.
	 */
	public static Category getInstance(String name) {
		return LogManager.getLogger(name, factory);
	}

	/**
	 * This method overrides {@link Logger#getInstance} by supplying
	 * its own factory type as a parameter.
	 */
	public static Category getInstance(Class clazz) {
		return LogManager.getLogger(clazz.getName(), factory);
	}

	/**
	 * This method overrides {@link Logger#getLogger} by supplying
	 * its own factory type as a parameter.
	 */
	public static Logger getLogger(String name) {
		return LogManager.getLogger(name, factory);
	}

	/**
	 * This method overrides {@link Logger#getLogger} by supplying
	 * its own factory type as a parameter.
	 */
	public static org.apache.log4j.Logger getLogger(Class clazz) {
		return LogManager.getLogger(clazz.getName(), factory);
	}

	/**
	 * {@inheritDoc}
	 * Note: In this implementation, this change is not persistent,
	 * meaning that if the application is restarted, the log level will revert to the level defined in the
	 * ESAPI SecurityConfiguration properties file.
	 */
	public void setLevel(int level) {
		try {
			super.setLevel(convertESAPILeveltoLoggerLevel(level));
		} catch (IllegalArgumentException e) {
			this.error(org.owasp.esapi.Logger.SECURITY_FAILURE, "", e);
		}
	}
	
	/**
	 * {@inheritDoc}
	 * Explanation: Since this class extends Log4j's Logger class which has a
	 * {@code getLevel()} method that returns {@code extended by org.apache.log4j.Level},
	 * we can't simply have a {@code getLevel()} that simply returns an {@code int}.
	 * Hence we renamed it to {@code getESAPILevel()}.
	 */
	public int getESAPILevel() {
		return super.getLevel().toInt();
	}

	/**
	 * Converts the ESAPI logging level (a number) into the levels used by Java's logger.
	 * @param level The ESAPI to convert.
	 * @return The Log4J logging Level that is equivalent.
	 * @throws IllegalArgumentException if the supplied ESAPI level doesn't make a level that is currently defined.
	 */
	private static Level convertESAPILeveltoLoggerLevel(int level) {
		switch (level) {
		case org.owasp.esapi.Logger.OFF:
			return Level.OFF;
		case org.owasp.esapi.Logger.FATAL:
			return Level.FATAL;
		case org.owasp.esapi.Logger.ERROR:
			return Level.ERROR;
		case org.owasp.esapi.Logger.WARNING:
			return Level.WARN;
		case org.owasp.esapi.Logger.INFO:
			return Level.INFO;
		case org.owasp.esapi.Logger.DEBUG:
			return Level.DEBUG; //fine
		case org.owasp.esapi.Logger.TRACE:
			return Level.TRACE; //finest
		case org.owasp.esapi.Logger.ALL:
			return Level.ALL;
		default: {
			throw new IllegalArgumentException("Invalid logging level. Value was: " + level);
		}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void always(EventType type, String message, Throwable throwable) {
		log(Level.OFF, type, message, throwable);	// Seems like Level.ALL is what we
													// would want here, but this is what
													// works. Level.ALL does not.
	}

	/**
	 * {@inheritDoc}
	 */
	public void always(EventType type, String message) {
		always(type, message, null);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void trace(EventType type, String message, Throwable throwable) {
		log(Level.TRACE, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void trace(EventType type, String message) {
		log(Level.TRACE, type, message, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public void debug(EventType type, String message, Throwable throwable) {
		log(Level.DEBUG, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void debug(EventType type, String message) {
		log(Level.DEBUG, type, message, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public void info(EventType type, String message) {
		log(Level.INFO, type, message, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public void info(EventType type, String message, Throwable throwable) {
		log(Level.INFO, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void warning(EventType type, String message, Throwable throwable) {
		log(Level.WARN, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void warning(EventType type, String message) {
		log(Level.WARN, type, message, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public void error(EventType type, String message, Throwable throwable) {
		log(Level.ERROR, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void error(EventType type, String message) {
		log(Level.ERROR, type, message, null);
	}

	/**
	 * {@inheritDoc}
	 */
	public void fatal(EventType type, String message, Throwable throwable) {
		log(Level.FATAL, type, message, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	public void fatal(EventType type, String message) {
		log(Level.FATAL, type, message, null);
	}

	/**
	 * Always log the specified message as a {@code SECURITY_AUDIT} event type.
	 * 
	 * @param message	The {@code String} representation of the specified message as
	 * 					logged by calling the object's {@code toString()} method.
	 */
	public void always(Object message) {
		this.always(message, null);
	}

	/**
	 * Always log the specified message as a {@code SECURITY_AUDIT} event type, along
	 * with its associated exception stack trace (if any).
	 * 
	 * @param message	The {@code String} representation of the specified message as
	 * 					logged by calling the object's {@code toString()} method.
	 */
	public void always(Object message, Throwable throwable) {
		String toLog = (message instanceof String) ? (String) message : message.toString();
		this.always(org.owasp.esapi.Logger.SECURITY_AUDIT, toLog, throwable);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void trace(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.trace(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void trace(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.trace(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.debug(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void debug(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.debug(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.info(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void info(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.info(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warn(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.warning(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void warn(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.warning(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.error(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void error(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.error(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(Object message) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.fatal(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void fatal(Object message, Throwable throwable) {

		String toLog = (message instanceof String) ? (String) message : message.toString();

		this.fatal(org.owasp.esapi.Logger.EVENT_UNSPECIFIED, toLog, throwable);
	}

	/**
	 * Log the message after optionally encoding any special characters that might be dangerous when viewed
	 * by an HTML based log viewer. Also encode any carriage returns and line feeds to prevent log
	 * injection attacks. This logs all the supplied parameters plus the user ID, user's source IP, a logging
	 * specific session ID, and the current date/time.
	 *
	 * It will only log the message if the current logging level is enabled, otherwise it will
	 * discard the message.
	 *
	 * @param level defines the set of recognized logging levels (TRACE, INFO, DEBUG, WARNING, ERROR, FATAL)
	 * @param type the type of the event (SECURITY SUCCESS, SECURITY FAILURE, EVENT SUCCESS, EVENT FAILURE)
	 * @param message the message to be logged
	 * @param throwable the {@code Throwable} from which to generate an exception stack trace.
	 */
	private void log(Level level, EventType type, String message, Throwable throwable) {

		// Check to see if we need to log.
		if (!isEnabledFor(level)) {
			return;
		}

		// ensure there's something to log
		if (message == null) {
			message = "";
		}

		// ensure no CRLF injection into logs for forging records
		String clean = message.replace('\n', '_').replace('\r', '_');
		if (ESAPI.securityConfiguration().getLogEncodingRequired()) {
			clean = ESAPI.encoder().encodeForHTML(message);
			if (!message.equals(clean)) {
				clean += " (Encoded)";
			}
		}

		// log server, port, app name, module name -- server:80/app/module
		StringBuilder appInfo = new StringBuilder();
		if (ESAPI.currentRequest() != null && logServerIP) {
			appInfo.append(ESAPI.currentRequest().getLocalAddr()).append(":").append(ESAPI.currentRequest().getLocalPort());
		}
		if (logAppName) {
			appInfo.append("/").append(applicationName);
		}
		appInfo.append("/").append(getName());

		//get the type text if it exists
		String typeInfo = "";
		if (type != null) {
			typeInfo += type + " ";
		}

		// log the message
		log(level, "[" + typeInfo + getUserInfo() + " -> " + appInfo + "] " + clean, throwable);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isDebugEnabled() {
		return isEnabledFor(Level.DEBUG);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isErrorEnabled() {
		return isEnabledFor(Level.ERROR);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isFatalEnabled() {
		return isEnabledFor(Level.FATAL);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isInfoEnabled() {
		return isEnabledFor(Level.INFO);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean isTraceEnabled() {
		return isEnabledFor(Level.TRACE);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isWarningEnabled() {
		return isEnabledFor(Level.WARN);
	}

	public String getUserInfo() {
		// create a random session number for the user to represent the user's 'session', if it doesn't exist already
		String sid = null;
		HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
		if (request != null) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				sid = (String) session.getAttribute("ESAPI_SESSION");
				// if there is no session ID for the user yet, we create one and store it in the user's session
				if (sid == null) {
					sid = "" + ESAPI.randomizer().getRandomInteger(0, 1000000);
					session.setAttribute("ESAPI_SESSION", sid);
				}
			}
		}

		// log user information - username:session@ipaddr
		User user = ESAPI.authenticator().getCurrentUser();
		String userInfo = "";
		//TODO - make type logging configurable
		if (user != null) {
			userInfo += user.getAccountName() + ":" + sid + "@" + user.getLastHostAddress();
		}

		return userInfo;
	}
	
}