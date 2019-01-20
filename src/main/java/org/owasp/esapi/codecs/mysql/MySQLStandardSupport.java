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
package org.owasp.esapi.codecs.mysql;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.owasp.esapi.codecs.PushbackSequence;

/**
 * Helper class for the MySQLCodec which manages the encode/decode behavior for
 * MySQL Standard mode.
 * 
 * 
 * <pre>
 *   NUL (0x00) --> \0  [This is a zero, not the letter O]
 *   BS  (0x08) --> \b
 *   TAB (0x09) --> \t
 *   LF  (0x0a) --> \n
 *   CR  (0x0d) --> \r
 *   SUB (0x1a) --> \Z
 *   "   (0x22) --> \"
 *   %   (0x25) --> \%
 *   '   (0x27) --> \'
 *   \   (0x5c) --> \\
 *   _   (0x5f) --> \_ 
 *   <br>
 *   all other non-alphanumeric characters with ASCII values less than 256  --> \c
 *   where 'c' is the original non-alphanumeric character.
 * </pre>
 * 
 * 
 * @see <a href=
 *      "https://dev.mysql.com/doc/refman/8.0/en/string-literals.html">MySQL 8.0
 *      String Literals</a>
 * @see <a href=
 *      "https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping">OWASP
 *      SQL_Injection_Prevention_Cheat_Sheet#MySQL_Escaping</a>
 */
/* package */ class MySQLStandardSupport implements MySQLModeSupport {

    private MySQLCodec codecRef;

    public MySQLStandardSupport(MySQLCodec codec) {
        this.codecRef = codec;
    }

    public String encodeCharacter(Character c) {
        char ch = c.charValue();
        // check for alphanumeric characters
        String hex = codecRef.getHexForNonAlphanumeric(ch);

        if (hex == null) {
            return "" + ch;
        }
        if (ch == 0x00)
            return "\\0";
        if (ch == 0x08)
            return "\\b";
        if (ch == 0x09)
            return "\\t";
        if (ch == 0x0a)
            return "\\n";
        if (ch == 0x0d)
            return "\\r";
        if (ch == 0x1a)
            return "\\Z";
        if (ch == 0x22)
            return "\\\"";
        if (ch == 0x25)
            return "\\%";
        if (ch == 0x27)
            return "\\'";
        if (ch == 0x5c)
            return "\\\\";
        if (ch == 0x5f)
            return "\\_";
        return "\\" + c;
    }

    public Character decodeCharacter(PushbackSequence<Character> input) {
        input.mark();
        Character first = input.next();
        if (first == null) {
            input.reset();
            return null;
        }

        // if this is not an encoded character, return null
        if (first.charValue() != '\\') {
            input.reset();
            return null;
        }

        Character second = input.next();
        if (second == null) {
            input.reset();
            return null;
        }

        if (second.charValue() == '0') {
            return Character.valueOf((char) 0x00);
        } else if (second.charValue() == 'b') {
            return Character.valueOf((char) 0x08);
        } else if (second.charValue() == 't') {
            return Character.valueOf((char) 0x09);
        } else if (second.charValue() == 'n') {
            return Character.valueOf((char) 0x0a);
        } else if (second.charValue() == 'r') {
            return Character.valueOf((char) 0x0d);
        } else if (second.charValue() == 'Z') {
            return Character.valueOf((char) 0x1a);
        } else if (second.charValue() == '\"') {
            return Character.valueOf((char) 0x22);
        } else if (second.charValue() == '%') {
            return Character.valueOf((char) 0x25);
        } else if (second.charValue() == '\'') {
            return Character.valueOf((char) 0x27);
        } else if (second.charValue() == '\\') {
            return Character.valueOf((char) 0x5c);
        } else if (second.charValue() == '_') {
            return Character.valueOf((char) 0x5f);
        } else {
            return second;
        }
    }
}