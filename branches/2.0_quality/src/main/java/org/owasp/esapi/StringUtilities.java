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
import java.util.regex.Pattern;

/**
 * String utilities used in various filters.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 * href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public class StringUtilities {

	private static final Pattern p = Pattern.compile( "\\s");
	public static String replaceLinearWhiteSpace( String input ) {
		return p.matcher(input).replaceAll( " " );
	}
	
	/**
	 * Removes all unprintable characters from a string 
	 * and replaces with a space.
	 * @param input
	 * @return the stripped value
	 */
	public static String stripControls( String input ) {
		StringBuilder sb = new StringBuilder();
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
     * Union multiple character arrays.
     * 
     * @param list the char[]s to union
     * @return the union of the char[]s
     */
    public static char[] union(char[]... list) {
    	StringBuilder sb = new StringBuilder();
    	
    	for (char[] characters : list) {
	        for (int i = 0; i < list.length; i++) {
	            if (!contains(sb, characters[i]))
	                sb.append(list[i]);
	        }
    	}

        char[] toReturn = new char[sb.length()];
        sb.getChars(0, sb.length(), toReturn, 0);
        Arrays.sort(toReturn);
        return toReturn;
    }


	/**
     * Returns true if the character is contained in the provided StringBuilder.
     * @param input 	The input
     * @param c 		The character to check for to see if {@code input} contains.
     * @return			True if the specified character is contained; false otherwise.
     */
    public static boolean contains(StringBuilder input, char c) {
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) == c)
                return true;
        }
        return false;
    }

}