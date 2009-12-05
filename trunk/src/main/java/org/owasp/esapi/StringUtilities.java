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

    /**
     * Returns the replace value if the value of test is null, "null", or ""
     *
     * @param test The value to test
     * @param replace The replacement value
     * @return The correct value
     */
    public static String replaceNull( String test, String replace ) {
        return ( test == null || "null".equalsIgnoreCase( test.trim() ) || "".equals( test.trim() ) ) ? replace : test;
    }

    /**
     * Calculate the Edit Distance between 2 Strings as a measure of similarity.
     *
     * For example, if the strings GUMBO and GAMBOL are passed in, the edit distance
     * is 2, since GUMBO transforms into GAMBOL by replacing the 'U' with an 'A' and
     * adding an 'L'.
     *
     * Original Implementation of this algorithm by Michael Gilleland, adapted by
     * Chas Emerick for the Apache-Commons project
     * http://www.merriampark.com/ldjava.htm
     *
     * @param s The source string
     * @param t The target String
     * @return The edit distance between the 2 strings
     */
    public static int getLevenshteinDistance (String s, String t) {
      if (s == null || t == null) {
        throw new IllegalArgumentException("Strings must not be null");
      }

      int n = s.length(); // length of s
      int m = t.length(); // length of t

      if (n == 0) {
        return m;
      } else if (m == 0) {
        return n;
      }

      int p[] = new int[n+1]; //'previous' cost array, horizontally
      int d[] = new int[n+1]; // cost array, horizontally
      int _d[]; //placeholder to assist in swapping p and d

      // indexes into strings s and t
      int i; // iterates through s
      int j; // iterates through t

      char t_j; // jth character of t

      int cost; // cost

      for (i = 0; i<=n; i++) {
         p[i] = i;
      }

      for (j = 1; j<=m; j++) {
         t_j = t.charAt(j-1);
         d[0] = j;

         for (i=1; i<=n; i++) {
            cost = s.charAt(i-1)==t_j ? 0 : 1;
            // minimum of cell to the left+1, to the top+1, diagonally left and up +cost
            d[i] = Math.min(Math.min(d[i-1]+1, p[i]+1),  p[i-1]+cost);
         }

         // copy current distance counts to 'previous row' distance counts
         _d = p;
         p = d;
         d = _d;
      }

      // our last action in the above loop was to switch d and p, so p now
      // actually has the most recent cost counts
      return p[n];
    }

    /**
     * Check to ensure that a {@code String} is not null or empty (after optional
     * trimming of leading and trailing whitespace). Usually used with
     * assertions, as in
     * <pre>
     * 		assert StringUtils.notNullOrEmpty(cipherXform, true) :
     * 								"Cipher transformation may not be null or empty!";
     * </pre>
     *
     * @param str	The {@code String} to be checked.
     * @param trim	If {@code true}, the string is first trimmed before checking
     * 				to see if it is empty, otherwise it is not.
     * @return		True if the string is null or empty (after possible
     * 				trimming); otherwise false.
     * @since 2.0
     */
    public static boolean notNullOrEmpty(String str, boolean trim) {
    	if ( trim ) {
    		return !( str == null || str.trim().equals("") );
    	} else {
    		return !( str == null || str.equals("") );
    	}
    }

    /**
     * Returns true if String is empty ("") or null.
     */
    public static boolean isEmpty(String str) {
        return str == null || str.length() == 0;
    }
}