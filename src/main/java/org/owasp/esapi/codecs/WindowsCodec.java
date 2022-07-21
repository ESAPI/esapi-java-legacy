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
 * Implementation of the Codec interface for '^' encoding from Windows command shell.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class WindowsCodec extends AbstractCharacterCodec {


    /**
     * {@inheritDoc}
     *
     * Returns Windows shell encoded character (which is ^)
     *
     * @param immune
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

        return "^" + c;
    }


    /**
     * {@inheritDoc}
     *
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     * <p>
     * Formats all are legal both upper/lower case:
     *   ^x - all special characters
     */
    public Character decodeCharacter( PushbackSequence<Character> input ) {
        input.mark();
        Character first = input.next();
        if ( first == null ) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if ( first.charValue() != '^' ) {
            input.reset();
            return null;
        }

        Character second = input.next();
        return second;
    }

}