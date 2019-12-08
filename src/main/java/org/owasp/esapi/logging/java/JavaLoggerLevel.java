package org.owasp.esapi.logging.java;

import java.util.logging.Level;

/**
 *  A custom logging level defined between Level.SEVERE and Level.WARNING in logger.
 */
public class JavaLoggerLevel extends Level {

    protected static final long serialVersionUID = 1L;

    /**
	 * Defines a custom error level below SEVERE but above WARNING since this level isn't defined directly
	 * by java.util.Logger already.
	 */
	public static final Level ERROR_LEVEL = new JavaLoggerLevel( "ERROR", Level.SEVERE.intValue() - 1);
	
	/**
	 * Constructs an instance of a JavaLoggerLevel which essentially provides a mapping between the name of
	 * the defined level and its numeric value.
	 * 
	 * @param name The name of the JavaLoggerLevel
	 * @param value The associated numeric value
	 */
	private JavaLoggerLevel(String name, int value) {
		super(name, value);
	}
}
    