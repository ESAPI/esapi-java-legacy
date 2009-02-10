/*
 * OWASP ESAPI WAF
 *
 * ModSecurity for Java M3 (Milestone 3)
 * Copyright (c) 2004-2005 Ivan Ristic <ivanr@webkreator.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package org.owasp.esapi.filters.waf.util;

public class Decoder {

    public static char x2c(char c1, char c2) throws InvalidURLEncodingException {
        int i1 = 0, i2 = 0;

        if ((c1 >= '0')&&(c1 <= '9')) {
            i1 = (int)(c1 - '0');
        }
        else if ((c1 >= 'a')&&(c1 <= 'f')) {
            i1 = 10 + (int)(c1 - 'a');
        }
        else if ((c1 >= 'A')&&(c1 <= 'F')) {
            i1 = 10 + (int)(c1 - 'A');
        }
        else {
            throw new InvalidURLEncodingException();
        }

        if ((c2 >= '0')&&(c2 <= '9')) {
            i2 = (int)(c2 - '0');
        }
        else if ((c2 >= 'a')&&(c2 <= 'f')) {
            i2 = 10 + (int)(c2 - 'a');
        }
        else if ((c2 >= 'A')&&(c2 <= 'F')) {
            i2 = 10 + (int)(c2 - 'A');
        }
        else {
            throw new InvalidURLEncodingException();
        }

        return (char)((i1 * 16) + i2);
    }

    public static String decodeURLEncodedUnicode(String value) throws InvalidURLEncodingException {
        StringBuffer sb = new StringBuffer(value.length());
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if (c == '+') c = ' ';
            else if (c == '%') {
                if ( (i + 5 < n) && ((value.charAt(i + 1) == 'u')||(value.charAt(i + 1) == 'U')) ) {
                    // unicode
                    char c1 = Decoder.x2c(value.charAt(i + 2), value.charAt(i + 3));
                    char c2 = Decoder.x2c(value.charAt(i + 4), value.charAt(i + 5));
                    char cs[] = Character.toChars(((int)c1) * 256 + (int)c2);
                    sb.append(cs[0]);
                }
                else if (i + 2 < n) {
                    // normal URL-encoded character
                    sb.append(Decoder.x2c(value.charAt(++i), value.charAt(++i)));
                }
                else throw new InvalidURLEncodingException();
            }
            else sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static String decodeURLEncoded(String value) throws InvalidURLEncodingException {
        StringBuffer sb = new StringBuffer(value.length());
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if (c == '+') c = ' ';
            else if (c == '%') {
                if (i + 2 >= n) throw new InvalidURLEncodingException();
                c = Decoder.x2c(value.charAt(++i), value.charAt(++i));
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static String decodeEscaped(String value) throws InvalidEscapeSequenceException {
        // TODO should web support \xHH and similar?

        StringBuffer sb = new StringBuffer(value.length());
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if ((c == '\\')&&(i + 1 < n)) {
                i++;
                c = value.charAt(i);
                switch(c) {
                    case '0' :
                        c = '\0';
                        break;
                    case 'b' :
                        c = '\b';
                        break;
                    case 'f' :
                        c = '\f';
                        break;
                    case 'n' :
                        c = '\n';
                        break;
                    case 'r' :
                        c = '\r';
                        break;
                    case 't' :
                        c = '\t';
                        break;
                }
                sb.append(c);
            } else {
                sb.append(c);
            }
            i++;
        }
        return sb.toString();
    }

    public static String compressWhitespace(String value) {
        StringBuffer sb = new StringBuffer(value.length());
        boolean previousWasWhite = false;
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if (Character.isWhitespace(c)) {
                if (previousWasWhite == false) {
                    sb.append(' ');
                    previousWasWhite = true;
                }
            } else {
                previousWasWhite = false;
                sb.append(c);
            }
            i++;
        }
        return sb.toString();
    }

    public static String compressSlashes(String value) {
        StringBuffer sb = new StringBuffer(value.length());
        boolean previousWasSlash = false;
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if (c == '/') {
                if (previousWasSlash == false) {
                    sb.append('/');
                    previousWasSlash = true;
                }
            } else {
                previousWasSlash = false;
                sb.append(c);
            }
            i++;
        }
        return sb.toString();
    }

    public static String convertBackSlashes(String value) {
        StringBuffer sb = new StringBuffer(value.length());
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if (c == '\\') c = '/';
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static String removeSelfReferences(String value) {
        StringBuffer sb = new StringBuffer(value.length());
        //boolean previousWasSlash = false;
        int i = 0, n = value.length();
        while(i < n) {
            char c = value.charAt(i);
            if ((c == '/')&&(i + 2 < n)&&(value.charAt(i + 1) == '.')&&(value.charAt(i + 2) == '/')) {
                i += 2;
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    public static String convertToLowercase(String value) {
        return value.toLowerCase();
    }
}