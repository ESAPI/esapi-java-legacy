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

/**
 *  A custom logging level defined between Level.SEVERE and Level.WARNING in logger.
 */
public class ESAPIErrorJavaLevel extends Level {

    protected static final long serialVersionUID = 1L;

    /**
     * Defines a custom error level below SEVERE but above WARNING since this level isn't defined directly
     * by java.util.Logger already.
     */
    public static final Level ERROR_LEVEL = new ESAPIErrorJavaLevel( "ERROR", Level.SEVERE.intValue() - 1);

    /**
     * Constructs an instance of a JavaLoggerLevel which essentially provides a mapping between the name of
     * the defined level and its numeric value.
     * 
     * @param name The name of the JavaLoggerLevel
     * @param value The associated numeric value
     */
    private ESAPIErrorJavaLevel(String name, int value) {
        super(name, value);
    }
}
