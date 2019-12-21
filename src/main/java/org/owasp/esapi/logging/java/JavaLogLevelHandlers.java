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
	ALL(Level.ALL),
	ERROR(ESAPIErrorJavaLevel.ERROR_LEVEL);

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
