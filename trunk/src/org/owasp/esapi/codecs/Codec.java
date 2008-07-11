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
 * Base Codec class.
 * 
 * 
 * 
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class Codec {

	public Codec() {
	}

	public String getEncodedString( String input ) {
		return null;
	}
	
	public String getDecodedString( String input ) {
		return null;
	}
	

	/**
	 * Returns the decoded version of the character at index if it is encoded using
	 * this encoder's scheme, otherwise returns null.
	 */
	public Character getDecodedCharacter( PushbackString input ) {
		return null;
	}

	public String getEncodedCharacter( Character c ) {
		return null;
	}
}