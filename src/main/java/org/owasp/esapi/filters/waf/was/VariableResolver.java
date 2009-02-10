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

import java.io.File;
import java.util.Enumeration;

import javax.servlet.http.*;
import org.owasp.esapi.filters.waf.*;

public class VariableResolver {

    private HttpTransaction tran;

    private int[] normalizationFunctions;

    public VariableResolver(int[] normalizationFunctions, HttpTransaction tran) {
        this.normalizationFunctions = normalizationFunctions;
        this.tran = tran;
    }

    public String getValue(Variable variable) {
        String r = null;

        switch(variable.code) {

            /* -- request variables ---------------------------- */

            case Variable.AUTH_TYPE :
                r = tran.msReq.getAuthType();
                break;

            case Variable.SESSION_ID :
                r = tran.msReq.getRequestedSessionId();
                break;

            case Variable.REQUEST_URI :
                r = tran.msReq.getRequestURI();
                break;

            case Variable.SCRIPT_NAME :
                r = tran.msReq.getServletPath();
                break;

            case Variable.REQUEST_METHOD :
                r = tran.msReq.getMethod();
                break;

            case Variable.REMOTE_ADDR :
                r = tran.msReq.getRemoteAddr();
                break;

            case Variable.REMOTE_HOST :
                r = tran.msReq.getRemoteHost();
                break;

            case Variable.REMOTE_USER :
                r = tran.msReq.getRemoteUser();
                break;

            case Variable.QUERY_STRING :
                r = tran.msReq.getQueryString();
                break;

            case Variable.PATH_TRANSLATED :
                r = tran.msReq.getPathTranslated();
                break;

            case Variable.PATH_INFO :
                r = tran.msReq.getPathInfo();
                break;

            case Variable.CONTENT_TYPE :
                r = tran.msReq.getContentType();
                break;

            case Variable.CONTENT_LENGTH :
                // TODO should we return an empty string if the length is -1?
                r = Integer.toString(tran.msReq.getContentLength());
                break;

            case Variable.SERVER_NAME :
                r = tran.msReq.getServerName();
                break;

            case Variable.SERVER_PORT :
                r = Integer.toString(tran.msReq.getServerPort());
                break;

            case Variable.SERVER_PROTOCOL :
                r = tran.msReq.getProtocol();
                break;

            case Variable.PARAMS :
                {
                    int count = 0;
                    for (Enumeration e = tran.msReq.getParameterNames(); e.hasMoreElements() ;) {
                        String paramName = (String)e.nextElement();
                        String paramValues[] = tran.msReq.getParameterValues(paramName);
                        count += paramValues.length;
                    }
                    return Integer.toString(count);
                }
                // break;

            case Variable.SINGLE_PARAMETER :
                r = tran.msReq.getParameter(variable.subName);
                break;

            case Variable.HEADERS :
                {
                    int count = 0;
                    for (Enumeration e = tran.msReq.getHeaderNames(); e.hasMoreElements() ;) {
                        String headerName = (String)e.nextElement();
                        for (Enumeration e2 = tran.msReq.getHeaders(headerName); e2.hasMoreElements() ;) {
                            count++;
                        }
                    }
                    return Integer.toString(count);
                }
                // break;

            case Variable.SINGLE_HEADER :
                if (variable.object != null) r = (String)variable.object;
                else {
                    // TODO error
                }
                break;

            case Variable.COOKIES :
                return Integer.toString(tran.msReq.getCookies().length);
                // break;

            case Variable.SINGLE_COOKIE :
                if (variable.object != null) r = ((Cookie)variable.object).getValue();
                else {
                    // TODO error
                }
                break;

            case Variable.RAW_BODY :
                r = tran.msReq.getBody();
                break;

            case Variable.FILES :
                {
                    int count = 0;
                    for (Enumeration e = tran.msReq.getFileNames(); e.hasMoreElements() ;) {
                        count++;
                    }
                    return Integer.toString(count);
                }
                // break;

            case Variable.SINGLE_FILE :
                if (variable.object != null) r = ((File)variable.object).getName();
                else {
                    // TODO error
                }
                break;

            /* -- response variables ---------------------------- */

            case Variable.RES_HEADERS :
                {
                    int count = 0;
                    for (Enumeration e = tran.msRes.getHeaderNames(); e.hasMoreElements() ;) {
                        String headerName = (String)e.nextElement();
                        for (Enumeration e2 = tran.msRes.getHeaders(headerName); e2.hasMoreElements() ;) {
                            count++;
                        }
                    }
                    return Integer.toString(count);
                }
                // break;

            case Variable.RES_SINGLE_HEADER :
                if (variable.object != null) r = (String)variable.object;
                else {
                    // TODO error
                }
                break;

            case Variable.RES_COOKIES :
                return Integer.toString(tran.msRes.getCookies().length);
                // break;

            case Variable.RES_SINGLE_COOKIE :
                if (variable.object != null) r = (String)variable.object;
                else {
                    // TODO error
                }
                break;

            case Variable.RES_STATUS :
                r = Integer.toString(tran.msRes.getStatus());
                break;

            case Variable.RES_CONTENT_TYPE :
                r = tran.msRes.getContentType();
                break;

            case Variable.RES_CONTENT_LENGTH :
                r = Integer.toString(tran.msRes.getContentLength());
                break;

            case Variable.RES_RAW_BODY :
                r = tran.msRes.getBody();
                break;

            default :
                // error
                System.err.println("Unknown variable type: " + variable.code);
                break;
        }

        switch(variable.operation) {

            case Variable.OPERATION_LENGTH :
                r = Integer.toString(r.length());
                break;

            case Variable.OPERATION_NAME :
                r = variable.subName;
                break;

            case Variable.OPERATION_NONE :
                // do nothing
                break;

            case Variable.OPERATION_F_SIZE :
                r = Long.toString(((File)variable.object).length());
                break;

            case Variable.OPERATION_F_TMP_FILENAME :
                r = ((File)variable.object).getName();
                break;

            default :
                // TODO error unknown operation
                break;
        }

        return r;
    }
}
