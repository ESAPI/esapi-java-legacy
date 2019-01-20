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
package org.owasp.esapi.codecs.mysql;

import org.owasp.esapi.codecs.AbstractCharacterCodec;
import org.owasp.esapi.codecs.PushbackSequence;

/**
 * Codec implementation which can be used to escape string literals in MySQL.
 * </br>
 * Implementation accepts 2 Modes as identified by the OWASP Recommended
 * escaping strategies:
 * <ul>
 * <li><b>ANSI</b> <br>
 * Simply encode all ' (single tick) characters with '' (two single ticks)</li>
 * <br>
 * <li><b>Standard</b>
 * 
 * <pre>
 *   NUL (0x00) --> \0  [This is a zero, not the letter O]
 *   BS  (0x08) --> \b
 *   TAB (0x09) --> \t
 *   LF  (0x0a) --> \n
 *   CR  (0x0d) --> \r
 *   SUB (0x1a) --> \Z
 *   "   (0x22) --> \"
 *   %   (0x25) --> \%
 *   '   (0x27) --> \'
 *   \   (0x5c) --> \\
 *   _   (0x5f) --> \_ 
 *   <br>
 *   all other non-alphanumeric characters with ASCII values less than 256  --> \c
 *   where 'c' is the original non-alphanumeric character.
 * </pre>
 * 
 * </li>
 * 
 * </ul>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com)
 *         <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * 
 * @see <a href=
 *      "https://dev.mysql.com/doc/refman/8.0/en/string-literals.html">MySQL 8.0
 *      String Literals</a>
 * @see <a href=
 *      "https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping">OWASP
 *      SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping</a>
 */
public class MySQLCodec extends AbstractCharacterCodec {
    /** Target MySQL Server is running in Standard MySQL (Default) mode. */
    public static final int MYSQL_MODE = MySQLMode.STANDARD.ordinal();
    /** Target MySQL Server is running in ANSI Mode */
    public static final int ANSI_MODE = MySQLMode.ANSI.ordinal();
	
    private final MySQLModeSupport modeSupport;
	
	/**
	 * Instantiate the MySQL codec
	 * 
	 * @param mode
	 * 			Mode has to be one of {MYSQL_MODE|ANSI_MODE} to allow correct encoding
     * @deprecated
     * @see {@link MySQLMode}
	 */
	public MySQLCodec( int mode ) {
		this (MySQLMode.findByKey(mode));
	}

    /**
     * Instantiate the MySQL Codec with the given SQL {@link MySQLMode}.
     * @param mode The mode the target server is running in
     */
    public MySQLCodec( MySQLMode mode ) {
        if (mode == null) {
            throw new IllegalArgumentException("MySQLMode reference cannot be null");
        }
        modeSupport = mode.getModeSupport(this);
    }


	/**
	 * {@inheritDoc}
     */
	public String encodeCharacter( char[] immune, Character c ) {
		char ch = c.charValue();
		
		// check for immune characters
		if ( containsCharacter( ch, immune ) ) {
			return c.toString();
		}
		
		return modeSupport.encodeCharacter(c);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public Character decodeCharacter( PushbackSequence<Character> input ) {
		return modeSupport.decodeCharacter(input);
	}
}