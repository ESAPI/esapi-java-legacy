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
 * @created 2019
 */
package org.owasp.esapi.logging.java;

import java.util.logging.Level;
import java.util.logging.Logger;

public enum JavaLogLevelHandlers implements JavaLogLevelHandler {

	SEVERE(Level.SEVERE),
	WARNING(Level.WARNING),
	INFO(Level.INFO),
	CONFIG(Level.CONFIG),
	FINE(Level.FINE),
	FINER(Level.FINER),
	FINEST(Level.FINEST),
	ALWAYS(ESAPICustomJavaLevel.ALWAYS_LEVEL),
	ERROR(ESAPICustomJavaLevel.ERROR_LEVEL);

	private final Level level;
	
	private JavaLogLevelHandlers(Level lvl) {
		this.level = lvl;
	}
	
	@Override
	public boolean isEnabled(Logger logger) {
		return logger.isLoggable(level);
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
