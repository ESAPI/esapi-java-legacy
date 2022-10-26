/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2022 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeffrey Walton (noloader .at. gmail.com)
 * @author Kevin Wall (kevin.w.wall .at. gmail.com)
 * @author Matt Seil (matt.seil .at. owasp.org)
 * @created 2022
 */
package org.owasp.esapi.codecs;

/**
 * Implementation of the Codec interface for JSON strings.
 * This class performs <a
 * href="https://datatracker.ietf.org/doc/html/rfc8259#section-7">String escaping</a>
 * on the entire string according to RFC 8259, Section 7.
 *
 * RFC 8259 requires conforming implementations use UTF-8. However, the ESAPI interfaces
 * utilize Java strings, which are UTF-16. This may cause problems during encoding and
 * decoding operations. To avoid some of the problems, convert the string to UTF-8 before
 * encoding and from UTF-8 after decoding. Ultimately the ESAPI encoder interfaces will
 * need modification to provide byte array arguments and return values.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8259#section-7">RFC 8259,
 * The JavaScript Object Notation (JSON) Data Interchange Format, Section 7</a>
 *
 * @author Jeffrey Walton (noloader .at. gmail.com)
 * @author Kevin Wall (kevin.w.wall .at. gmail.com)
 * @author Matt Seil (matt.seil .at. owasp.org)
 * @since July 31, 2022
 * @see org.owasp.esapi.Encoder
 */
public class JSONCodec extends AbstractIntegerCodec {


    /**
     * {@inheritDoc}
     *
     * Escape special characters in JSON strings.
     *
     * encodeCharacter will escape the characters Backspace (\b), Form Feed (\f),
     * Carriage Return (\r), Line Feed (\n), Tab (\t), Double Quote (") and Backslash (\).
     * If the character is a control character (U+0000 through U+001f), then it will be
     * Unicode encoded (\u0000 through \u001f). If the character is not special or in the
     * user supplied immune list, then the character is returned unescaped. If the
     * character is null then an empty string is returned.
     *
     * WARNING: This method will silently discard an invalid code point according to
     * the result of {@code Character.isValidCodePoint( int )} method.
     *
     * @param immune character array of whitelist characters which should not be encoded
     * @param c the character to encode if not in the immune list
     * @return encoded character if the character is special, and the character otherwise.
     */
    public String encodeCharacter( char[] immune, Character c ) {
        if ( c == null ) {
            return "";
        }

        return encodeCharacter(immune, charToCodepoint( c ));
    }

    /**
     * {@inheritDoc}
     *
     * Escape special characters in JSON strings.
     *
     * encodeCharacter will escape the characters Backspace (\b), Form Feed (\f),
     * Carriage Return (\r), Line Feed (\n), Tab (\t), Double Quote (") and Backslash (\).
     * If the character is a control character (U+0000 through U+001f), then it will be
     * Unicode encoded (\u0000 through \u001f). If the character is not special or in the
     * user supplied immune list, then the character is returned unescaped. If the
     * character is null then an empty string is returned.
     *
     * WARNING: This method will silently discard an invalid code point according to
     * the result of {@code Character.isValidCodePoint( int )} method.
     *
     * @param immune character array of whitelist characters which should not be encoded
     * @param c the character to encode if not in the immune list
     * @return encoded character if the character is special, and the character otherwise.
     */
    public String encodeCharacter( char[] immune, int codePoint )
        throws IllegalArgumentException {

        // Per the docs for HTMLEntityCodec: "WARNING: This method will silently discard
        // invalid code points per the call to Character.isValidCodePoint( int ) method.
        // WARNING!! Character based Codecs will silently transform code points that are
        // not legal UTF code points into garbage data as they will cast them to chars.
        if ( Character.isValidCodePoint( codePoint ) == false ) {
            // throw new IllegalArgumentException( "Invalid codepoint '" + String.format("0x%04X", codePoint) + "'." );
            return "";
        }

        if ( immune != null ) {
            // More efficient than sort and binary search. If the immune array
            // was presorted, then this could be O(log n). But we can't add the
            // precondition now. It is too late in the game.
            for ( Character ch : immune ) {
                if ( charToCodepoint( ch ) == codePoint ) {
                    return new String(Character.toChars(codePoint));
                }
            }
        }

        // Per the RFC... Two-character sequence escape representations of some
        // popular characters
        switch ( codePoint ) {
            case '\b': return "\\b";
            case '\f': return "\\f";
            case '\r': return "\\r";
            case '\n': return "\\n";
            case '\t': return "\\t";
            case '"':  return "\\\"";
            case '/':  return  "\\/";
            case '\\': return "\\\\";
        }

        // Per the RFC... All Unicode characters may be placed within the
        // quotation marks, except for the characters that MUST be escaped:
        // quotation mark, reverse solidus, and the control characters
        // (U+0000 through U+001F).
        if ( codePoint <=  0x1f ) {

            return String.format("\\u%04x", codePoint);
        }

        return new String(Character.toChars(codePoint));
    }


    /**
     * {@inheritDoc}
     *
     * Decodes special characters in encoded JSON strings.
     *
     * decodeCharacter will decode the encoded character sequences for popular characters
     * Backspace (\b), Form Feed (\f), Carriage Return (\r), Line Feed (\n), Tab (\t),
     * Double Quote ("), Forward slash (/) and Backslash (\). The function will also decode
     * six-character sequences of \u0000 - \uffff. If the character is not encoded then a
     * null character is returned.
     *
     * @param input a character sequence to decode
     * @return the decoded version of the encoded character starting at index,
     *     or null otherwise
     *
     * @throws IllegalArgumentException
     *     if an invalid character sequence is encountered
     */
    public Integer decodeCharacter( PushbackSequence<Integer> input )
        throws IllegalArgumentException {

        input.mark();

        Integer first = input.next(), second = null;
        if ( first == null || first.intValue() != '\\' ) {
            input.reset();
            return null;
        }

        String errorMessage = null;

        try
        {
            errorMessage = "Invalid JSON escape representation";

            if ( (second = input.next()) == null ) {
                throw new IllegalArgumentException();
            }

            // Per the RFC... Two-character sequence escape representations of some popular characters
            switch ( second.intValue() ) {
                case 'b': return (int)'\b';
                case 'f': return (int)'\f';
                case 'r': return (int)'\r';
                case 'n': return (int)'\n';
                case 't': return (int)'\t';
                case '"': return (int)'\"';
                case '/': return  (int)'/';
                case '\\': return (int)'\\';
            }

            errorMessage = "Invalid JSON two-character escape representation";

            // Per the RFC... All characters may be escaped as a six-character sequence: a reverse solidus,
            // followed by the lowercase letter u, followed by four hexadecimal digits that encode the
            // character's code point. The hexadecimal letters A through F can be uppercase or lowercase.
            // So, for example, a string containing only a single reverse solidus character may be represented
            // as "\u005C".
            if ( second.intValue() == 'u' ) {

                errorMessage = "Invalid JSON six-character escape representation";

                return (convertToInt( input.next() ) << 12) +
                       (convertToInt( input.next() ) <<  8) +
                       (convertToInt( input.next() ) <<  4) +
                       (convertToInt( input.next() ) <<  0);
            }

            // Do nothing. Fall into throw below.
        }
        catch (IllegalArgumentException e)
        {
            // Do nothing. Fall into throw below.
        }

        // Catch all. The escaped character sequence was invalid.
        input.reset();
        throw new IllegalArgumentException( errorMessage );
    }

    protected int charToCodepoint( Character ch ) {

        final String s = Character.toString(ch);
        assert (s.length() == 1) : "Ooops";

        return s.codePointAt(0);
    }

    protected int convertToInt( Integer hexDigit ) {

        if ( hexDigit == null ) {
            throw new IllegalArgumentException( "Cannot convert from '<null>' to int." );
        }

        final int value = Character.digit( hexDigit.intValue(), 16 );

        if ( value < 0 || value >= 16 ) {
            throw new IllegalArgumentException( "Cannot convert from hexadecimal '" + hexDigit.toString() + "' to int." );
        }

        return value;
    }

}
