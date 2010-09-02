/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Patrick Higgins
 * @created 2010
 */
package org.owasp.esapi.codecs;

public class CodecUtil {

    /**
     * Initialize an array to mark which characters are to be encoded. Store the hex
     * string for that character to save time later. If the character shouldn't be
     * encoded, then store null.
     */
    private static final String[] hex = new String[256];
    
    /**
     * A zero-length array of characters.
     */
    public static final char[] EMPTY_CHARS = new char[0];

    static {
        for ( char c = 0; c < 0xFF; c++ ) {
            if ( c >= 0x30 && c <= 0x39 || c >= 0x41 && c <= 0x5A || c >= 0x61 && c <= 0x7A ) {
                hex[c] = null;
            } else {
                hex[c] = Integer.toHexString(c).intern();
            }
        }
    }
    /**
     * Lookup the hex value of any character that is not alphanumeric.
     * @param c The character to lookup.
     * @return, return null if alphanumeric or the character code
     *  in hex.
     */
    public static String getHexForNonAlphanumeric(char c)
    {
        if(c<0xFF)
            return hex[c];
        return Integer.toHexString(c);
    }

    /**
     * Utility to search a char[] for a specific char.
     * 
     * @param c
     * @param array
     * @return
     */
    public static boolean containsCharacter( char c, char[] array ) {
        for (int i = 0; i < array.length; i++) {
            if (c == array[i]) return true;
        }
        return false;
    }

}
