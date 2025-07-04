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
 * The Codec interface defines a set of methods for encoding and decoding application level encoding schemes,
 * such as HTML entity encoding and percent encoding (aka URL encoding). Codecs are used in output encoding
 * and canonicalization.  The design of these codecs allows for character-by-character decoding, which is
 * necessary to detect double-encoding and the use of multiple encoding schemes, both of which are techniques
 * used by attackers to bypass validation and bury encoded attacks in data.
 * </p><p>
 * Other than the interfaces, very few of these concrete classes are intended to be used directly.
 * Rather, most of them are used through implementations of the {@link org.owasp.esapi.Encoder}
 * interface. While the OWASP team over the years have made every effort to be extra cautious, the
 * various {@code Codec} implementations can offer NO GUARANTEE of safety if the client is
 * using these {@code Codec} classes <i>directly</i>. Therefore, if the client is using
 * these classes directly, it is highly advised to practice security-in-depth
 * and also perform canonicalization, followed by strict input validation, both
 * prior to encoding and after decoding, to protect your application from input-based
 * attacks.
 * </p>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 *
 * @author Matt Seil (mseil .at. owasp.org)
 * @since June 1, 2017
 * @see org.owasp.esapi.Encoder
 * @see org.owasp.esapi.Validator
 */
public interface Codec<T> {
    /**
     * Encode a String so that it can be safely used in a specific context.
     *
     * @param immune
     * @param input
     *         the String to encode
     * @return the encoded String
     */
    public String encode(char[] immune, String input);

    /**
     * Default implementation that should be overridden in specific codecs.
     *
     * @param immune
     *         array of chars to NOT encode.  Use with caution.
     * @param c
     *         the Character to encode
     * @return
     *         the encoded Character
     */
    public String encodeCharacter( char[] immune, Character c );

    /**
     * Default codepoint implementation that should be overridden in specific codecs.
     *
     * @param immune
     * @param codePoint
     *         the integer to encode
     * @return
     *         the encoded Character
     */
    public String encodeCharacter( char[] immune, int codePoint );

    /**
     * Decode a String that was encoded using the encode method in this Class
     *
     * @param input
     *         the String to decode
     * @return
     *        the decoded String
     */
    public String decode(String input);

    /**
     * Returns the decoded version of the next character from the input string and advances the
     * current character in the {@code PushbackSequence}.  If the current character is not encoded, this
     * method <i>MUST</i> reset the {@code PushbackString}.
     *
     * @param input    the Character to decode
     *
     * @return the decoded Character
     */
    public T decodeCharacter( PushbackSequence<T> input );

    /**
     * Lookup the hex value of any character that is not alphanumeric.
     * @param c The character to lookup.
     * @return return null if alphanumeric or the character code in hex.
     */
    public String getHexForNonAlphanumeric(char c);

    /**
     * Lookup the hex value of any character that is not alphanumeric.
     * @param c The character to lookup.
     * @return return null if alphanumeric or the character code in hex.
     */
    public String getHexForNonAlphanumeric(int c);

    /**
     * Convert the {@code char} parameter to its octal representation.
     * @param c the character for which to return the new representation.
     * @return the octal representation.
     */
    public String toOctal(char c);

    /**
     * Convert the {@code char} parameter to its hexadecimal representation.
     * @param c the character for which to return the new representation.
     * @return the hexadecimal representation.
     */
    public String toHex(char c);

    /**
     * Convert the {@code int} parameter to its hexadecimal representation.
     * @param c the character for which to return the new representation.
     * @return the hexadecimal representation.
     */
    public String toHex(int c);

    /**
     * Utility to search a char[] for a specific char.
     *
     * @param c
     * @param array
     * @return True if the supplied array contains the specified character. False otherwise.
     */
    public boolean containsCharacter( char c, char[] array );

}
