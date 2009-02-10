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

package org.owasp.esapi.filters.waf;

import java.io.*;
import java.net.*;
import java.util.*;
import java.text.*;
import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.esapi.filters.waf.util.*;

public class MsHttpServletResponse extends HttpServletResponseWrapper {

    private static final int INTERCEPT_OFF = 0;
    private static final int INTERCEPT_ON = 1;
    private static final int INTERCEPT_OBSERVE_ONLY = 2;

    public static final String DEFAULT_CHARACTER_ENCODING = "ISO-8859-1";

    private int interceptMode = INTERCEPT_ON;

    private ArrayList headers = new ArrayList();

    private ArrayList cookies = new ArrayList();

    private int status = -1;

    private boolean committed = false;

    private boolean suspended = false;

    private boolean destroyed = false;

    private String statusMessage;

    private String contentType;

    private String characterEncoding;

    private int contentLength = -1;

    private Locale locale;

    private MsOutputStream msOutputStream;

    private MsWriter msWriter;

    protected SimpleDateFormat formats[] = {
        new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US),
        new SimpleDateFormat("EEEEEE, dd-MMM-yy HH:mm:ss zzz", Locale.US),
        new SimpleDateFormat("EEE MMMM d HH:mm:ss yyyy", Locale.US)
    };

    private class Header {
        String name;
        String value;

        Header(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    public MsHttpServletResponse(HttpServletResponse response) {
        super(response);

        characterEncoding = DEFAULT_CHARACTER_ENCODING;
        TimeZone GMT_ZONE = TimeZone.getTimeZone("GMT");
        formats[0].setTimeZone(GMT_ZONE);
        formats[1].setTimeZone(GMT_ZONE);
        formats[2].setTimeZone(GMT_ZONE);
        locale = Locale.getDefault();
    }

    public void destroy() throws IOException {
        if (destroyed == true) return;

        if (interceptMode == INTERCEPT_ON) {
            if (status != -1) {
                if (statusMessage == null) super.setStatus(status);
                else super.setStatus(status, statusMessage);
            }
            if (contentType != null) super.setContentType(contentType);
            if (characterEncoding != null) super.setCharacterEncoding(characterEncoding);
            if (contentLength != -1) super.setContentLength(contentLength);
            if (locale != null) super.setLocale(locale);

            // send cookies
            for(int i = 0, n = cookies.size(); i < n; i++) {
                super.addCookie((Cookie)cookies.get(i));
            }

            // send headers
            for(int i = 0, n = headers.size(); i < n; i++) {
                Header h = (Header)headers.get(i);
                // TODO don't send our cookie headers because
                // they are not well implemented yet. Cookies
                // are sent directly
                if (h.name.compareTo("Set-Cookie") != 0) {
                    super.addHeader(h.name, h.value);
                }
            }
        }

        if (msWriter != null) msWriter.commit();
        if (msOutputStream != null) msOutputStream.commit();

        destroyed = true;
    }

    public String getBody() {
        if (msWriter != null) {
            return msWriter.toString();
        }
        if (msOutputStream != null) {
            return msOutputStream.toString(getCharacterEncoding());
        }
        return null;
    }

    public void setSuspended(boolean suspended) {
        this.suspended = true;
        if (msWriter != null) msWriter.setSuspended(suspended);
        if (msOutputStream != null) msOutputStream.setSuspended(suspended);
    }

    /* -- ServletResponse methods ---------------------------------------- */

    public String getContentType() {
        if (interceptMode != INTERCEPT_OFF) {
            return contentType;
        }
        return super.getContentType();
    }

    public ServletOutputStream getOutputStream() throws IllegalStateException, IOException {
        if (interceptMode != INTERCEPT_OFF) {
            if (msWriter != null) throw new IllegalStateException();
            if (msOutputStream == null) msOutputStream = new MsOutputStream(super.getOutputStream());
            if (interceptMode == INTERCEPT_ON) msOutputStream.setBuffering(true);
            return msOutputStream;
        }
        else {
            return super.getOutputStream();
        }
    }

    public PrintWriter getWriter() throws IllegalStateException, IOException {
        if (interceptMode != INTERCEPT_OFF) {
            if (msOutputStream != null) throw new IllegalStateException();
            if (msWriter == null) msWriter = new MsWriter(super.getWriter());
            if (interceptMode == INTERCEPT_ON) msWriter.setBuffering(true);
            return msWriter;
        }
        else {
            return super.getWriter();
        }
    }

    public void setCharacterEncoding(String charset) {
        if (interceptMode != INTERCEPT_ON) {
            super.setCharacterEncoding(charset);
        }
        if (interceptMode != INTERCEPT_OFF) {
            characterEncoding = charset;
        }
    }

    public void setContentLength(int contentLength) {
        if (interceptMode != INTERCEPT_ON) {
            super.setContentLength(contentLength);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.contentLength = contentLength;
            headers.add(new Header("Content-Length", Integer.toString(contentLength)));
        }
    }

    public void setContentType(String contentType) {
        if (interceptMode != INTERCEPT_ON) {
            super.setContentType(contentType);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.contentType = contentType;
            headers.add(new Header("Content-Type", contentType));
        }
    }

    public void setBufferSize(int size) throws IllegalStateException {
        super.setBufferSize(size);
    }

    public int getBufferSize() {
        return super.getBufferSize();
    }

    public void flushBuffer() throws IOException {
        if (interceptMode != INTERCEPT_ON) {
            super.flushBuffer();
        }
        if (interceptMode != INTERCEPT_OFF) {
            committed = true;
        }
    }

    public void resetBuffer() {
        if (interceptMode != INTERCEPT_ON) {
            super.resetBuffer();
        }
        if (interceptMode != INTERCEPT_OFF) {
            if (committed) throw new IllegalStateException();

            if (msWriter != null) msWriter.reset();
            if (msOutputStream != null) msOutputStream.reset();
        }
    }

    public boolean isCommitted() {
        if (interceptMode != INTERCEPT_OFF) {
            return committed;
        }
        return super.isCommitted();
    }

    public void reset() throws IllegalStateException {
        if (interceptMode != INTERCEPT_ON) {
            super.reset();
        }
        if (interceptMode != INTERCEPT_OFF) {
            if (committed) throw new IllegalStateException();

            status = 200;
            characterEncoding = DEFAULT_CHARACTER_ENCODING;
            contentType = null;
            contentLength = -1;
            headers.clear();
            status = 200;
            statusMessage = null;

            if (msWriter != null) msWriter.reset();
            if (msOutputStream != null) msOutputStream.reset();
        }
    }

    public void setLocale(Locale locale) {
        if (interceptMode != INTERCEPT_ON) {
            super.setLocale(locale);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.locale = locale;
        }
    }

    public Locale getLocale() {
        if (interceptMode != INTERCEPT_OFF) {
            return locale;
        }
        return super.getLocale();
    }

    /* -- HttpServletResponse methods ------------------------------------ */

    public void addCookie(Cookie cookie) {
        if (interceptMode != INTERCEPT_ON) {
            super.addCookie(cookie);
        }
        if (interceptMode != INTERCEPT_OFF) {
            cookies.add(cookie);
            // TODO improve; these headers will not be
            // sent to the client
            StringBuffer sb = new StringBuffer();
            sb.append(cookie.getName());
            sb.append("=");
            if (cookie.getDomain() != null) sb.append("; domain=" + cookie.getDomain());
            if (cookie.getPath() != null) sb.append("; path=" + cookie.getPath());
            if (cookie.getSecure()) sb.append("; secure");
            headers.add(new Header("Set-Cookie", sb.toString()));
        }
    }

    public void addDateHeader(String name, long value) {
        SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        this.addHeader(name, FastHttpDateFormat.formatDate(value, format));
    }

    public void addHeader(String name, String value) {
        if (interceptMode != INTERCEPT_ON) {
            super.addHeader(name, value);
        }
        if (interceptMode != INTERCEPT_OFF) {
            headers.add(new Header(name, value));
        }
    }

    public void addIntHeader(String name, int value) {
        this.addHeader(name, Integer.toString(value));
    }

    public boolean containsHeader(String name) {
        if (interceptMode == INTERCEPT_OFF) return super.containsHeader(name);
        else {
            for(int i = 0, n = headers.size(); i < n; i++) {
                Header h = (Header)headers.get(i);
                if (h.name.compareTo(name) == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    public void setDateHeader(String name, long value) {
        SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
        format.setTimeZone(TimeZone.getTimeZone("GMT"));
        this.setHeader(name, FastHttpDateFormat.formatDate(value, format));
    }

    public void setHeader(String name, String value) {
        if (interceptMode != INTERCEPT_ON) {
            super.setHeader(name, value);
        }
        if (interceptMode != INTERCEPT_OFF) {
            for(int i = 0, n = headers.size(); i < n; i++) {
                Header h = (Header)headers.get(i);
                if (h.name.compareTo(name) == 0) {
                    headers.remove(i);
                    i--;
                }
            }
            headers.add(new Header(name, value));
        }
    }

    public void setIntHeader(String name, int value) {
        this.setHeader(name, Integer.toString(value));
    }

    public void setStatus(int status) {
        if (interceptMode != INTERCEPT_ON) {
            super.setStatus(status);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.status = status;
        }
    }

    public void setStatus(int status, String message) {
        if (interceptMode != INTERCEPT_ON) {
            super.setStatus(status, message);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.status = status;
            this.statusMessage = message;
        }
    }

    public void sendError(int status) throws IOException {
        if (interceptMode != INTERCEPT_ON) {
            super.sendError(status);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.status = status;
            this.setSuspended(true);
        }
    }

    public void sendError(int status, String message) throws IOException {
        if (interceptMode != INTERCEPT_ON) {
            super.sendError(status);
        }
        if (interceptMode != INTERCEPT_OFF) {
            this.status = status;
            this.statusMessage = message;
            this.setSuspended(true);
        }
    }

    /* -- Inspection methods ---------------------------------------------- */

    // TODO throw exception when interceptMode set to OFF

    public Cookie[] getCookies() {
        return (Cookie[])cookies.toArray(new Cookie[cookies.size()]);
    }

    public int getStatus() {
        return status;
    }

    public int getContentLength() {
        return contentLength;
    }

    public long getDateHeader(String name) throws IllegalArgumentException {
        String value = this.getHeader(name);
        if (value == null) return -1;

        long result = FastHttpDateFormat.parseDate(value, formats);
        if (result == -1) throw new IllegalArgumentException(value);

        return result;
    }

    public String getHeader(String name) {
        for(int i = 0, n = headers.size(); i < n; i++) {
            Header h = (Header)headers.get(i);
            if (h.name.compareTo(name) == 0) return h.value;
        }
        return null;
    }

    public Enumeration getHeaderNames() {
        Hashtable headerNames = new Hashtable();
        for(int i = 0, n = headers.size(); i < n; i++) {
            Header h = (Header)headers.get(i);
            headerNames.put(h.name, h.value);
        }
        return headerNames.keys();
    }

    public int getIntHeader(String name) throws NumberFormatException {
        String value = this.getHeader(name);
        if (value == null) return -1;
        return Integer.parseInt(value);
    }

    public Enumeration getHeaders(String name) {
        Vector headerValues = new Vector();
        for(int i = 0, n = headers.size(); i < n; i++) {
            Header h = (Header)headers.get(i);
            if (h.name.compareTo(name) == 0) headerValues.add(h.value);
        }
        return headerValues.elements();
    }
}