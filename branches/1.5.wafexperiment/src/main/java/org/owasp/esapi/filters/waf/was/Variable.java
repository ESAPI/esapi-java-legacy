/*
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

package org.owasp.esapi.filters.waf.was;

public class Variable {
    public static final int REMOTE_ADDR = 1;
    public static final int CONTENT_TYPE = 2;
    public static final int PARAMS = 3;
    public static final int SERVER_NAME = 4;
    public static final int SERVER_PORT = 5;
    public static final int REMOTE_HOST = 6;
    public static final int CONTENT_LENGTH = 7;
    public static final int SERVER_PROTOCOL = 8;
    public static final int REMOTE_USER = 9;
    public static final int QUERY_STRING = 10;
    public static final int PATH_TRANSLATED = 11;
    public static final int PATH_INFO = 12;
    public static final int REQUEST_METHOD = 13;
    public static final int AUTH_TYPE = 14;
    public static final int SESSION_ID = 15;
    public static final int REQUEST_URI = 16;
    public static final int SCRIPT_NAME = 17;
    public static final int HEADERS = 18;
    public static final int SINGLE_HEADER = 19;
    public static final int COOKIES = 20;
    public static final int RAW_BODY = 21;
    public static final int SINGLE_PARAMETER = 22;
    public static final int SINGLE_COOKIE = 23;
    public static final int FILES = 24;
    public static final int SINGLE_FILE = 25;

    public static final int RES_STATUS = 101;
    public static final int RES_CONTENT_TYPE = 102;
    public static final int RES_CONTENT_LENGTH = 103;
    public static final int RES_RAW_BODY = 104;
    public static final int RES_HEADERS = 105;
    public static final int RES_SINGLE_HEADER = 106;
    public static final int RES_COOKIES = 107;
    public static final int RES_SINGLE_COOKIE = 108;

    public static final int OPERATION_NONE = 0;
    public static final int OPERATION_LENGTH = 1;
    public static final int OPERATION_NAME = 2;
    public static final int OPERATION_VALUE = 3;
    // public static final int OPERATION_COLLECTION_SIZE = 4;

    public static final int OPERATION_F_SIZE = 100;
    public static final int OPERATION_F_CONTENT_TYPE = 101;
    public static final int OPERATION_F_FILENAME = 102;
    public static final int OPERATION_F_TMP_FILENAME = 103;

    String fullName;

    int code;

    String subName;

    int operation;

    Object object;

    public boolean isIdentical(Variable v) {
        if ((v.code == code)&&(v.subName.compareTo(subName) == 0)&&(v.operation == operation)) return true;
        else return false;
    }

    public String toString() {
        return("Variable [code=" + code + ", subName=" + subName + ", operation=" + operation + "]");
    }
}
