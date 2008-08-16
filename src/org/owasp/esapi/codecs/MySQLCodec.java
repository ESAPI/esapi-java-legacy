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
package org.owasp.esapi.codecs;



/**
 * Implementation of the Codec interface for MySQL strings. See http://mirror.yandex.ru/mirrors/ftp.mysql.com/doc/refman/5.0/en/string-syntax.html
 * for more information.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class MySQLCodec implements Codec {

	public static final int MYSQL_MODE = 0;
	public static final int ANSI_MODE = 1;
	
	private int mode = 0;
	
	public MySQLCodec( int mode ) {
		this.mode = mode;
	}

	public String encode( String input ) {
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt(i);
			sb.append( encodeCharacter( new Character( c ) ) );
		}
		return sb.toString();
	}

	/**
	 * Returns quote-encoded character
	 */
	public String encodeCharacter( Character c ) {
		switch( mode ) {
			case ANSI_MODE: return encodeCharacterANSI( c );
			case MYSQL_MODE: return encodeCharacterMySQL( c );
		}
		return null;
	}
	
	private String encodeCharacterANSI( Character c ) {
		if ( c.charValue() == '\'' )
        	return "\'\'";
        return ""+c;
	}

	private String encodeCharacterMySQL( Character c ) {
		char ch = c.charValue();
		if ( ch == 0x00 ) return "\\0";
		if ( ch == 0x08 ) return "\\b";
		if ( ch == 0x09 ) return "\\t";
		if ( ch == 0x0a ) return "\\n";
		if ( ch == 0x0d ) return "\\r";
		if ( ch == 0x1a ) return "\\z";
		if ( ch == 0x22 ) return "\\\"";
		if ( ch == 0x25 ) return "\\%";
		if ( ch == 0x27 ) return "\\'";
		if ( ch == 0x5c ) return "\\\\";
		if ( ch == 0x5f ) return "\\_";
	    return "\\" + c;
	}
		
	public String decode( String input ) {
		StringBuffer sb = new StringBuffer();
		PushbackString pbs = new PushbackString( input );
		while ( pbs.hasNext() ) {
			Character c = decodeCharacter( pbs );
			if ( c != null ) {
				sb.append( c );
			} else {
				sb.append( pbs.next() );
			}
		}
		return sb.toString();
	}
	
	
	/**
	 * Returns the decoded version of the character starting at index, or
	 * null if no decoding is possible.
	 * 
	 * Formats all are legal (case sensitive)
	 *   In ANSI_MODE '' decodes to '
	 *   In MYSQL_MODE \x decodes to x (or a small list of specials)
	 */
	public Character decodeCharacter( PushbackString input ) {
		switch( mode ) {
			case ANSI_MODE: return decodeCharacterANSI( input );
			case MYSQL_MODE: return decodeCharacterMySQL( input );
		}
		return null;
	}

	private Character decodeCharacterANSI( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '\'' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( second.charValue() != '\'' ) {
			input.reset();
			return null;
		}
		return( new Character( '\'' ) );
	}

	private Character decodeCharacterMySQL( PushbackString input ) {
		input.mark();
		Character first = input.next();
		if ( first == null ) {
			input.reset();
			return null;
		}
		
		// if this is not an encoded character, return null
		if ( first.charValue() != '\\' ) {
			input.reset();
			return null;
		}

		Character second = input.next();
		if ( second == null ) {
			input.reset();
			return null;
		}
		
		if ( second.charValue() == '0' ) {
			return new Character( (char)0x00 );
		} else if ( second.charValue() == 'b' ) {
			return new Character( (char)0x08 );
		} else if ( second.charValue() == 't' ) {
			return new Character( (char)0x09 );
		} else if ( second.charValue() == 'n' ) {
			return new Character( (char)0x0a );
		} else if ( second.charValue() == 'r' ) {
			return new Character( (char)0x0d );
		} else if ( second.charValue() == 'z' ) {
			return new Character( (char)0x1a );
		} else if ( second.charValue() == '\"' ) {
			return new Character( (char)0x22 );
		} else if ( second.charValue() == '%' ) {
			return new Character( (char)0x25 );
		} else if ( second.charValue() == '\'' ) {
			return new Character( (char)0x27 );
		} else if ( second.charValue() == '\\' ) {
			return new Character( (char)0x5c );
		} else if ( second.charValue() == '_' ) {
			return new Character( (char)0x5f );
		} else {
			return second;
		}
	}

}