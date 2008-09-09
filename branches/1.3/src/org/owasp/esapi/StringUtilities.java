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
package org.owasp.esapi;

import java.util.Arrays;

/**
 * String utilities used in various filters.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class StringUtilities {

	/**
	 * Removes all unprintable characters from a string 
	 * and replaces with a space for use in an HTTP header
	 * @param input
	 * @return the stripped header
	 */
	public static String stripControls( String input ) {
		StringBuffer sb = new StringBuffer();
		for ( int i=0; i<input.length(); i++ ) {
			char c = input.charAt( i );
			if ( c > 0x20 && c < 0x7f ) {
				sb.append( c );
			} else {
				sb.append( ' ' );
			}
		}
		return sb.toString();
	}

	
    /**
     * Union two character arrays.
     * 
     * @param c1 the c1
     * @param c2 the c2
     * @return the char[]
     */
    public static char[] union(char[] c1, char[] c2) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < c1.length; i++) {
            if (!contains(sb, c1[i]))
                sb.append(c1[i]);
        }
        for (int i = 0; i < c2.length; i++) {
            if (!contains(sb, c2[i]))
                sb.append(c2[i]);
        }
        char[] c3 = new char[sb.length()];
        sb.getChars(0, sb.length(), c3, 0);
        Arrays.sort(c3);
        return c3;
    }


	/**
     * Returns true if the character is contained in the provided StringBuffer.
     */
    public static boolean contains(StringBuffer haystack, char c) {
        for (int i = 0; i < haystack.length(); i++) {
            if (haystack.charAt(i) == c)
                return true;
        }
        return false;
    }

}