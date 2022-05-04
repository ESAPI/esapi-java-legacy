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
 * Implementation of the {@code Codec} interface for '\' encoding from Unix command shell (bash lineage, not csh lineage).
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class UnixCodec extends AbstractCharacterCodec {

    /**
     * {@inheritDoc}
     * 
     * @return the backslash-encoded character
     *
     * @param immune Array of characters that should not be encoded. Use with caution! All
     *               alphanumeric characters are "immune" by default so you needn't
     *               include them.
     */
    public String encodeCharacter( char[] immune, Character c ) {
        char ch = c.charValue();
        
        // check for immune characters
        if ( containsCharacter( ch, immune ) ) {
            return ""+ch;
        }
        
        // check for alphanumeric characters
        String hex = super.getHexForNonAlphanumeric( ch );
        if ( hex == null ) {
            return ""+ch;
        }
        
        return "\\" + c;
    }
    
    
    /**
     * {@inheritDoc}
     *
     * <p>
     * Formats all are legal both upper/lower case:
     * <pre>
     *   \x - all special characters
     * </pre>
     * 
     * @return the decoded version of the character starting at index, or
     * null if no decoding is possible.
     */
    public Character decodeCharacter( PushbackSequence<Character> input ) {
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
        return second;
    }

}
