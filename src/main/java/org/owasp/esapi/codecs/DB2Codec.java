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
 */
package org.owasp.esapi.codecs;


/**
 * Implementation of the Codec interface for IBM Db2 strings.
 * This function will only protect you from SQLi in limited situations.
 * To improve your chances of success, you made also need to do some
 * additional canonicalization and input validation first. Before using this class,
 * please be sure to read the "SECURITY WARNING" in
 * {@link org.owasp.esapi.Encoder#encodeForSQL}
 * before using this particular {@link org.owasp.esapi.codecs.Codec} and raising your hope of finding
 * a silver bullet to kill all the SQLi werewolves.
 *
 * @author Sivasankar Tanakala (stanakal@TRS.NYC.NY.US)
 * @since October 26, 2010
 * @see org.owasp.esapi.Encoder
 * @see <a href="https://github.com/ESAPI/esapi-java-legacy/blob/develop/documentation/ESAPI-security-bulletin13.pdf">
 *              ESAPI Security Bulletin #13</a>
 * @deprecated  This class is considered dangerous and not easily made safe and thus under strong
 *              consideration to be removed within 1 years time after the 2.7.0.0 release. Please
 *              see the referenced ESAPI Security Bulletin #13 for further details.
 */
@Deprecated
public class DB2Codec extends AbstractCharacterCodec {

    public String encodeCharacter(char[] immune, Character c) {

        if (c.charValue() == '\'')
            return "\'\'";

        if (c.charValue() == ';')
            return ".";

        return "" + c;
    }

    public Character decodeCharacter(PushbackString input) {

        input.mark();
        Character first = input.next();

        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null

        if (first.charValue() != '\'') {
            input.reset();
            return null;
        }

        Character second = input.next();

        if (second == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (second.charValue() != '\'') {
            input.reset();
            return null;
        }

        return (Character.valueOf('\''));
    }
}
