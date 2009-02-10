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

import java.util.*;
import javax.servlet.http.*;
import org.owasp.esapi.filters.waf.*;

public class VariableFactory {

    public static final int CONTEXT_REQUEST = 1;
    public static final int CONTEXT_RESPONSE = 2;

    public static String extractSubname(String t) {
        String subName = null;

        int i = t.indexOf("["), j = t.indexOf("]");
        if ((i == -1)||(j == -1)||(i > j)) return null;

        subName = t.substring(i + 1, j);
        if ((subName.charAt(0) == '\'')&&(subName.charAt(subName.length() - 1) == '\'')) {
            subName = subName.substring(1, subName.length() - 1);
        } else
        if ((subName.charAt(0) == '"')&&(subName.charAt(subName.length() - 1) == '"')) {
            subName = subName.substring(1, subName.length() - 1);
        }

        return subName;
    }

    static void populateRequestVariable_PARAMS(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String paramName = extractSubname(t1);
        if ((paramName == null)||(paramName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to request parameters");
            }

            if (t2 != null) {
                if (paramName == null) {
                    // operations against parameter collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the request
                        v.code = Variable.PARAMS;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "request.params.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for request parameter collection: " + t2);
                    }
                }
                else {
                    // operations against individual headers
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                    else {
                        throw new ParsingException("Invalid operation for request parameters: " + t2);
                    }
                }
            }

            // TODO this is not good enough, there can be many
            // parameters with the same name
            for (Enumeration e = tran.msReq.getParameterNames(); e.hasMoreElements() ;) {
                Variable v2 = new Variable();
                v2.code = Variable.SINGLE_PARAMETER;
                v2.operation = v.operation;
                v2.subName = (String)e.nextElement();
                v2.fullName = "request.params[\"" + v2.subName + "\"]";
                r.add(v2);
            }
        } else {
            if (t2 != null) {
                if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                else if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation for request parameters: " + t2);
                }
            }

            // just one hparameter
            if (isReversed == false) {
                // add one variable to the list
                String[] parameterValues = tran.msReq.getParameterValues(paramName);
                for (int i = 0; i < parameterValues.length; i++) {
                    Variable v2 = new Variable();
                    v2.code = Variable.SINGLE_PARAMETER;
                    v2.operation = v.operation;
                    v2.subName = paramName;
                    v2.object = (String)parameterValues[i];
                    v2.fullName = "request.params[\"" + v2.subName + "\"]" + (t2 == null ? "" : t2);
                    r.add(v2);
                }
            } else {
                // remove this variable from the list
                v.code = Variable.SINGLE_PARAMETER;
                v.subName = paramName;
                Iterator i = r.iterator();
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateRequestVariable_HEADERS(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String headerName = extractSubname(t1);
        if ((headerName == null)||(headerName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to request headers");
            }

            if (t2 != null) {
                if (headerName == null) {
                    // operations against header collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the request
                        v.code = Variable.HEADERS;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "request.headers.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for request header collection: " + t2);
                    }
                }
                else {
                    // operations against individual headers
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                    else {
                        throw new ParsingException("Invalid operation for request headers: " + t2);
                    }
                }
            }

            // add one variable for every header in the
            // request
            for (Enumeration e = tran.msReq.getHeaderNames(); e.hasMoreElements() ;) {
                headerName = (String)e.nextElement();
                // there can be many headers with the same name
                // to speed things up we will resolve them here
                for (Enumeration e2 = tran.msReq.getHeaders(headerName); e2.hasMoreElements() ;) {
                    Variable v2 = new Variable();
                    v2.code = Variable.SINGLE_HEADER;
                    v2.operation = v.operation;
                    v2.subName = headerName;
                    v2.object = (String)e2.nextElement();
                    v2.fullName = "request.headers[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                    r.add(v2);
                }
            }
        } else {
            if (t2 != null) {
                if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                else if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation for request headers: " + t2);
                }
            }

            // just one header
            if (isReversed == false) {
                // add one variable to the list
                for (Enumeration e2 = tran.msReq.getHeaders(headerName); e2.hasMoreElements() ;) {
                    Variable v2 = new Variable();
                    v2.code = Variable.SINGLE_HEADER;
                    v2.operation = v.operation;
                    v2.subName = headerName;
                    v2.object = (String)e2.nextElement();
                    v2.fullName = "request.headers[\"" + v2.subName + "\"]" + (t2 == null ? "" : t2);
                    r.add(v2);
                }
            } else {
                // remove this variable from the list
                Iterator i = r.iterator();
                v.code = Variable.SINGLE_HEADER;
                v.subName = headerName;
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateRequestVariable_COOKIES(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String cookieName = extractSubname(t1);
        if ((cookieName == null)||(cookieName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to request cookies");
            }

            if (t2 != null) {
                if (cookieName == null) {
                    // operations against cookie collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the request
                        v.code = Variable.COOKIES;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "request.cookies.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for request cookie collection: " + t2);
                    }
                }
                else {
                    // operations against individual headers
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                    else {
                        throw new ParsingException("Invalid operation for request cookies: " + t2);
                    }
                }
            }

            // add one variable for every cookie in the request
            Cookie[] cookies = tran.msReq.getCookies();
            for(int i = 0; i < cookies.length; i++) {
                Variable v2 = new Variable();
                v2.code = Variable.SINGLE_COOKIE;
                v2.operation = v.operation;
                v2.subName = cookies[i].getName();
                v2.object = cookies[i].getValue();
                v2.fullName = "request.cookies[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                r.add(v2);
            }
        } else {
            if (t2 != null) {
                if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                else if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation for request cookies: " + t2);
                }
            }

            // just one cookie
            if (isReversed == false) {
                // add one variable to the list
                Cookie[] cookies = tran.msReq.getCookies();
                for(int i = 0; i < cookies.length; i++) {
                    if (cookieName.compareToIgnoreCase(cookies[i].getName()) == 0) {
                        Variable v2 = new Variable();
                        v2.code = Variable.SINGLE_COOKIE;
                        v2.operation = v.operation;
                        v2.subName = cookies[i].getName();
                        v2.object = cookies[i].getValue();
                        v2.fullName = "request.cookies[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                        r.add(v2);
                    }
                }
            } else {
                // remove this variable from the list
                Iterator i = r.iterator();
                v.code = Variable.SINGLE_COOKIE;
                v.subName = cookieName;
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateRequestVariable_FILES(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String fileName = extractSubname(t1);
        if ((fileName == null)||(fileName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to request files");
            }

            if (t2 != null) {
                if (fileName == null) {
                    // operations against file collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the request
                        v.code = Variable.FILES;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "request.files.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for request file collection: " + t2);
                    }
                }
                else {
                    // operations against individual files
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_F_SIZE;
                    else
                    if (t2.compareToIgnoreCase("content_type") == 0) v.operation = Variable.OPERATION_F_CONTENT_TYPE;
                    else
                    if (t2.compareToIgnoreCase("filename") == 0) v.operation = Variable.OPERATION_F_FILENAME;
                    else
                    if (t2.compareToIgnoreCase("tmp_filename") == 0) v.operation = Variable.OPERATION_F_TMP_FILENAME;
                    else {
                        throw new ParsingException("Invalid operation for request file: " + t2);
                    }
                }
            }

            // add one variable for every file in the request

            for (Enumeration e = tran.msReq.getFileNames(); e.hasMoreElements() ;) {
                fileName = (String)e.nextElement();
                Variable v2 = new Variable();
                v2.code = Variable.SINGLE_FILE;
                v2.operation = v.operation;
                v2.subName = fileName;
                v2.object = tran.msReq.getFile(fileName);
                v2.fullName = "request.files[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                r.add(v2);
            }
        } else {
            if (t2 != null) {
                // operations against individual files
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_F_SIZE;
                    else
                    if (t2.compareToIgnoreCase("content_type") == 0) v.operation = Variable.OPERATION_F_CONTENT_TYPE;
                    else
                    if (t2.compareToIgnoreCase("filename") == 0) v.operation = Variable.OPERATION_F_FILENAME;
                    else
                    if (t2.compareToIgnoreCase("tmp_filename") == 0) v.operation = Variable.OPERATION_F_TMP_FILENAME;
                    else {
                        throw new ParsingException("Invalid operation for request file: " + t2);
                    }
            }

            // just one file
            if (isReversed == false) {
                Variable v2 = new Variable();
                v2.code = Variable.SINGLE_FILE;
                v2.operation = v.operation;
                v2.subName = fileName;
                v2.object = tran.msReq.getFile(fileName);
                v2.fullName = "request.files[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                r.add(v2);
            } else {
                // remove this variable from the list
                Iterator i = r.iterator();
                v.code = Variable.SINGLE_FILE;
                v.subName = fileName;
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateResponseVariable_HEADERS(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String headerName = extractSubname(t1);
        if ((headerName == null)||(headerName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to response headers");
            }

            if (t2 != null) {
                if (headerName == null) {
                    // operations against header collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the request
                        v.code = Variable.RES_HEADERS;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "response.headers.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for response header collection: " + t2);
                    }
                }
                else {
                    // operations against individual headers
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                    else {
                        throw new ParsingException("Invalid operation for response headers: " + t2);
                    }
                }
            }

            // add one variable for every header in the
            // response
            for (Enumeration e = tran.msRes.getHeaderNames(); e.hasMoreElements() ;) {
                headerName = (String)e.nextElement();
                // there can be many headers with the same name
                // to speed things up we will resolve them here
                for (Enumeration e2 = tran.msRes.getHeaders(headerName); e2.hasMoreElements() ;) {
                    Variable v2 = new Variable();
                    v2.code = Variable.RES_SINGLE_HEADER;
                    v2.operation = v.operation;
                    v2.subName = headerName;
                    v2.object = (String)e2.nextElement();
                    v2.fullName = "response.headers[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                    r.add(v2);
                }
            }
        } else {
            if (t2 != null) {
                if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                else if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation for response headers: " + t2);
                }
            }

            // just one header
            if (isReversed == false) {
                // add one variable to the list
                for (Enumeration e2 = tran.msRes.getHeaders(headerName); e2.hasMoreElements() ;) {
                    Variable v2 = new Variable();
                    v2.code = Variable.RES_SINGLE_HEADER;
                    v2.operation = v.operation;
                    v2.subName = headerName;
                    v2.object = (String)e2.nextElement();
                    v2.fullName = "response.headers[\"" + v2.subName + "\"]" + (t2 == null ? "" : t2);
                    r.add(v2);
                }
            } else {
                // remove this variable from the list
                v.code = Variable.RES_SINGLE_HEADER;
                v.subName = headerName;
                Iterator i = r.iterator();
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateResponseVariable_COOKIES(List r, String t1, String t2, boolean isReversed, HttpTransaction tran) throws ParsingException {
        Variable v = new Variable();
        v.operation = Variable.OPERATION_NONE;
        String cookieName = extractSubname(t1);
        if ((cookieName == null)||(cookieName.compareTo("*") == 0)) {

            if (isReversed) {
                throw new ParsingException("The exclamation mark cannot be applied to response cookies");
            }

            if (t2 != null) {
                if (cookieName == null) {
                    // operations against cookie collection
                    if (t2.compareToIgnoreCase("size") == 0) {
                        // add just one variable - the number of
                        // headers in the response
                        v.code = Variable.RES_COOKIES;
                        v.operation = Variable.OPERATION_LENGTH;
                        v.fullName = "response.cookies.size";
                        r.add(v);
                        return;
                    } else {
                        throw new ParsingException("Invalid operation for response cookie collection: " + t2);
                    }
                }
                else {
                    // operations against individual headers
                    if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                    else
                    if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                    else {
                        throw new ParsingException("Invalid operation for response cookies: " + t2);
                    }
                }
            }

            // add one variable for every cookie in the request
            Cookie[] cookies = tran.msRes.getCookies();
            for(int i = 0; i < cookies.length; i++) {
                Variable v2 = new Variable();
                v2.code = Variable.RES_SINGLE_COOKIE;
                v2.operation = v.operation;
                v2.subName = cookies[i].getName();
                v2.object = cookies[i].getValue();
                v2.fullName = "response.cookies[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                r.add(v2);
            }
        } else {
            if (t2 != null) {
                if (t2.compareToIgnoreCase("size") == 0) v.operation = Variable.OPERATION_LENGTH;
                else if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation for response cookies: " + t2);
                }
            }

            // just one cookie
            if (isReversed == false) {
                // add one variable to the list
                Cookie[] cookies = tran.msRes.getCookies();
                for(int i = 0; i < cookies.length; i++) {
                    if (cookieName.compareToIgnoreCase(cookies[i].getName()) == 0) {
                        Variable v2 = new Variable();
                        v2.code = Variable.RES_SINGLE_COOKIE;
                        v2.operation = v.operation;
                        v2.subName = cookies[i].getName();
                        v2.object = cookies[i].getValue();
                        v2.fullName = "request.cookies[\"" + v2.subName + "\"]" + ((t2 == null) ? "" : "." + t2);
                        r.add(v2);
                    }
                }
            } else {
                // remove this variable from the list
                Iterator i = r.iterator();
                v.code = Variable.RES_SINGLE_COOKIE;
                v.subName = cookieName;
                while(i.hasNext()) {
                    Variable vx = (Variable)i.next();
                    if (vx.isIdentical(v) == true) {
                        i.remove();
                    }
               }
            }
        }
    }

    static void populateRequestVariable(List r, String t, boolean isReversed, HttpTransaction tran) throws ParsingException {
        // At this point t contains a variable name, without
        // the "request" prefix.
        String t1 = null, t2 = null;
        int j = t.indexOf(".");
        if (j != -1) {
            t1 = t.substring(0, j);
            t2 = t.substring(j + 1);
        } else {
            t1 = t;
        }

        // At this point t1 contains the first token
        // and t2 the rest (if present).

        // Special handling for built-in collections
        if (t1.startsWith("params")) {
            populateRequestVariable_PARAMS(r, t1, t2, isReversed, tran);
        }
        else if (t1.startsWith("files")) {
            populateRequestVariable_FILES(r, t1, t2, isReversed, tran);
        }
        else if (t1.startsWith("cookies")) {
            populateRequestVariable_COOKIES(r, t1, t2, isReversed, tran);
        }
        else if (t1.startsWith("headers")) {
            populateRequestVariable_HEADERS(r, t1, t2, isReversed, tran);
        }
        else {
            // Non-collections are handled here
            Variable v = new Variable();

            if (t1.compareToIgnoreCase("server_name") == 0) v.code = Variable.SERVER_NAME;
            else
            if (t1.compareToIgnoreCase("server_port") == 0) v.code = Variable.SERVER_PORT;
            else
            if (t1.compareToIgnoreCase("server_protocol") == 0) v.code = Variable.SERVER_PROTOCOL;
            else
            if (t1.compareToIgnoreCase("remote_addr") == 0) v.code = Variable.REMOTE_ADDR;
            else
            if (t1.compareToIgnoreCase("remote_host") == 0) v.code = Variable.REMOTE_HOST;
            else
            if (t1.compareToIgnoreCase("remote_user") == 0) v.code = Variable.REMOTE_USER;
            else
            if (t1.compareToIgnoreCase("query_string") == 0) v.code = Variable.QUERY_STRING;
            else
            if (t1.compareToIgnoreCase("path_translated") == 0) v.code = Variable.PATH_TRANSLATED;
            else
            if (t1.compareToIgnoreCase("path_info") == 0) v.code = Variable.PATH_INFO;
            else
            if (t1.compareToIgnoreCase("request_method") == 0) v.code = Variable.REQUEST_METHOD;
            else
            if (t1.compareToIgnoreCase("request_uri") == 0) v.code = Variable.REQUEST_URI;
            else
            if (t1.compareToIgnoreCase("auth_type") == 0) v.code = Variable.AUTH_TYPE;
            else
            if (t1.compareToIgnoreCase("session_id") == 0) v.code = Variable.SESSION_ID;
            else
            if (t1.compareToIgnoreCase("script_name") == 0) v.code = Variable.SCRIPT_NAME;
            else
            if (t1.compareToIgnoreCase("content_length") == 0) v.code = Variable.CONTENT_LENGTH;
            else
            if (t1.compareToIgnoreCase("content_type") == 0) v.code = Variable.CONTENT_TYPE;
            else
            if (t1.compareToIgnoreCase("raw_body") == 0) v.code = Variable.RAW_BODY;
            else {
                throw new ParsingException("Invalid request variable: " + t1);
            }

            // is there a variable attribute given?
            if (t2 != null) {
                if (t2.compareToIgnoreCase("length") == 0) v.operation = Variable.OPERATION_LENGTH;
                else
                if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid operation: " + t2);
                }
            }

            v.fullName = "request." + t1 + (t2 == null ? "" : "." + t2);
            r.add(v);
        }
    }

    static void populateResponseVariable(List r, String t, boolean isReversed, HttpTransaction tran) throws ParsingException {
        // At this point t contains a variable name, without
        // the "response" prefix.
        String t1 = null, t2 = null;
        int j = t.indexOf(".");
        if (j != -1) {
            t1 = t.substring(0, j);
            t2 = t.substring(j + 1);
        } else {
            t1 = t;
        }

        // At this point t1 contains the first token
        // and t2 the rest (if present).

        // Special handling for built-in collections
        if (t1.startsWith("headers")) {
            populateResponseVariable_HEADERS(r, t1, t2, isReversed, tran);
        }
        else if (t1.startsWith("cookies")) {
            populateResponseVariable_COOKIES(r, t1, t2, isReversed, tran);
        }
        else {
            // Non-collections are handled here
            Variable v = new Variable();

            if (t1.compareToIgnoreCase("status") == 0) v.code = Variable.RES_STATUS;
            else
            if (t1.compareToIgnoreCase("content_type") == 0) v.code = Variable.RES_CONTENT_TYPE;
            else
            if (t1.compareToIgnoreCase("content_length") == 0) v.code = Variable.RES_CONTENT_LENGTH;
            else
            if (t1.compareToIgnoreCase("raw_body") == 0) v.code = Variable.RES_RAW_BODY;
            else {
                throw new ParsingException("Invalid response variable: " + t1);
            }

            // is there a variable attribute given?
            if (t2 != null) {
                if (t2.compareToIgnoreCase("length") == 0) v.operation = Variable.OPERATION_LENGTH;
                else
                if (t2.compareToIgnoreCase("name") == 0) v.operation = Variable.OPERATION_NAME;
                else {
                    throw new ParsingException("Invalid variable operation: " + t2);
                }
            }

            v.fullName = "request." + t1 + ((t2 == null) ? "" : "." + t2);
            r.add(v);
        }
    }

    /**
     * Converts the textual variable definitions into
     * a collection containing Variable instances.
     */
    public static List createVariables(String args, HttpTransaction tran, int context) throws ParsingException {
        ArrayList r = new ArrayList();

        // separate the complete definition into
        // individual variables
        String[] tokens = Tokenizer.toStringArray(args);
        for(int i = 0; i < tokens.length; i++) {
            boolean isReversed = false;
            String varName = tokens[i];

            // allow "!" as the first character in the variable name
            if (varName.charAt(0) == '!') {
                isReversed = true;
                varName = varName.substring(1);
            }

            try {
                // For each variable, determine whether it is a
                // request variable or a response variable. Use the
                // name (for variables given with their fule name)
                // or the context to decide.
                int j = tokens[i].indexOf(".");
                if (j != -1) {
                    String firstPart = varName.substring(0, j);
                    if (firstPart.compareTo("request") == 0) {
                        populateRequestVariable(r, varName.substring(j + 1), isReversed, tran);
                    } else
                    if (firstPart.compareTo("response") == 0) {
                        populateResponseVariable(r, varName.substring(j + 1), isReversed, tran);
                    } else {
                        // Prefix is not given, assume the variable is in the context.
                        if (context == CONTEXT_REQUEST) populateRequestVariable(r, varName, isReversed, tran);
                        else populateResponseVariable(r, varName, isReversed, tran);
                    }
                }  else {
                    // Prefix is not given, assume the variable is in the context.
                    if (context == CONTEXT_REQUEST) populateRequestVariable(r, varName, isReversed, tran);
                    else populateResponseVariable(r, varName, isReversed, tran);
                }
            } catch(ParsingException pe) {
                throw new ParsingException("Error parsing \"" + tokens[i] + "\" (" + pe.getMessage() + ")");
            }
        }

        return r;
    }
}