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

package org.owasp.esapi.logging.log4j;


import org.apache.log4j.Level;
import org.apache.log4j.Logger;

/**
 * Enumeration capturing the propagation of Log4J level events.
 *
 */
public enum Log4JLogLevelHandlers implements Log4JLogLevelHandler {
	FATAL(Level.FATAL),
	ERROR(Level.ERROR),
	WARN(Level.WARN),
	INFO(Level.INFO),
	DEBUG(Level.DEBUG),
	TRACE(Level.TRACE),
	ALL(Level.ALL);

	private final Level level;
	
	private Log4JLogLevelHandlers(Level lvl) {
		this.level = lvl;
	}
	
	@Override
	public boolean isEnabled(Logger logger) {
		return logger.isEnabledFor(level);
	}

	@Override
	public void log(Logger logger, String msg) {
		logger.log(level, msg);
	}

	@Override
	public void log(Logger logger, String msg, Throwable th) {
		logger.log(level, msg, th);
	}    
}
