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
 * Implementation of the {@link org.owasp.esapi.codecs.Codec} interface for Oracle DB strings. 
 * This function will only protect you from SQLi in limited situations.
 * To improve your chances of success, you may also need to do some
 * additional canonicalization and input validation first. Before using this class,
 * please be sure to read the "<b>SECURITY WARNING</b>" in
 * {@link org.owasp.esapi.Encoder#encodeForSQL}
 * before using this particular {@link org.owasp.esapi.codecs.Codec} and raising your hope of finding
 * a silver bullet to kill all the SQLi werewolves.
 * </p><p>
 * <b>CAUTION:</b> This class has some known issues. During the investigation of
 * CVE-2025-5878, it was discovered that since this class' inception in
 * 2007, that Oracle databases also use \ (backslash) as a default escape char.
 * That was fundamental in the vulnerability, since the escape character itself
 * was not being escaped. We had originally planned to address this, but while
 * researching the issue, we discovered that not only was there a new default
 * escape character for Oracle SQL*Plus, but that developers could actually
 * override the default to a character of their choosing. (For details see
 * <a href="https://www.oreilly.com/library/view/oracle-sqlplus-the/0596007469/re62.html">SET ESCAPE</a>
 * and <a href="https://techjourney.net/how-to-escape-characters-in-oracle-plsql-queries/">
 * How to Escape Characters in Oracle PL/SQL Queries</a>.) The second instance is
 * especially scary, since it illustrates how a developer can potentially can
 * the default escape character as part of an ordinary SQL statement. We
 * realized that there is no way we can defend against this, so it seemed
 * pointless to even bother to try to quote default escape character passed in
 * as input when {@code OracleCodec} is used with the {@code Encoder.encodeForSQL}
 * interface. Therefore, you really should not use this, but if dead set in
 * still using this leg canon, it;s on you. You have been warned.
 * </p>
 * @see org.owasp.esapi.Encoder
 * @see <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin13.pdf">
 *              ESAPI Security Bulletin #13</a>
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @since June 1, 2007
 * @see <a href="http://oraqa.com/2006/03/20/how-to-escape-single-quotes-in-strings/">how-to-escape-single-quotes-in-strings</a>
 * @deprecated  This class is considered dangerous and not easily made safe and thus under strong
 *              consideration to be removed within 1 years time after the 2.7.0.0 release. Please
 *              see the referenced ESAPI Security Bulletin #13 for further details.
 */
@Deprecated
public class OracleCodec extends AbstractCharacterCodec {


    /**
     * {@inheritDoc}
     *
     * Encodes ' to ''
     *
     * Encodes ' to ''
     *
     * @param immune
     */
    public String encodeCharacter( char[] immune, Character c ) {
        if ( c.charValue() == '\'' )
            return "\'\'";
        return ""+c;
    }



    /**
     * {@inheritDoc}
     *
     * Returns the decoded version of the character starting at index, or
     * null if no decoding is possible.
     *
     * Formats all are legal
     *   '' decodes to '
     */
    public Character decodeCharacter( PushbackSequence<Character> input ) {
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
        return( Character.valueOf( '\'' ) );
    }

}
