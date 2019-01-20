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

import org.owasp.esapi.codecs.PushbackSequence;

/**
 * Helper class for the MySQLCodec which manages the encode/decode behavior for ANSI_QUOTES mode.
 * <br>
 * <b>ANSI</b> <br>
 * Simply encode all ' (single tick) characters with '' (two single ticks)
 * 
 * @see <a href=
 *      "https://dev.mysql.com/doc/refman/8.0/en/string-literals.html">MySQL 8.0
 *      String Literals</a>
 * @see <a href=
 *      "https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping">OWASP
 *      SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping</a>
 */
/*package*/ class MySQLAnsiSupport implements MySQLModeSupport {
    private static final char SINGLE_TICK = '\'';
    private static final String SINGLE_TICK_ESC= "\'\'";
   
	
	public String encodeCharacter(Character c ) {
		char ch = c.charValue();
		if ( ch == SINGLE_TICK ) {
		    return SINGLE_TICK_ESC;
		}
     
        return c.toString();
	}
	
	public Character decodeCharacter( PushbackSequence<Character> input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != SINGLE_TICK ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( second.charValue() != SINGLE_TICK ) {
			input.reset();
			return null;
		}
		return( Character.valueOf( SINGLE_TICK ) );
	}
}