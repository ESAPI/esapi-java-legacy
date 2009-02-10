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

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import javax.servlet.ServletOutputStream;

public class MsOutputStream extends ServletOutputStream {

    private boolean buffering = false;

    private ServletOutputStream sos;

    private ByteArrayOutputStream buffer;

    public MsOutputStream(ServletOutputStream sos) {
        super();
        this.sos = sos;
        buffer = new ByteArrayOutputStream();
    }

    public void setBuffering(boolean buffering) {
        this.buffering = buffering;
    }

    public String toString(String encoding) {
        String s = null;
        try {
            s = buffer.toString(encoding);
        } catch(UnsupportedEncodingException e) {
            // TODO error
            e.printStackTrace(System.err);
        }
        return s;
    }

    public byte[] toByteArray() {
        return buffer.toByteArray();
    }

    public void reset() {
        buffer.reset();
    }

    public void commit() throws IOException {
        if (!buffering) return;
        buffer.writeTo(sos);
        sos.close();
    }

    public void setSuspended(boolean suspended) {
        // TODO
    }

    /* -- OutputStream methods -------------------------------------- */

    public void write(int i) throws IOException {
        if (!buffering) sos.write(i);
        print(Integer.toString(i));
    }

    public void write(byte[] b) throws IOException {
        if (!buffering) sos.write(b, 0, b.length);
        buffer.write(b, 0, b.length);
    }

    public void write(byte[] b, int off, int len) throws IOException {
        if (!buffering) sos.write(b, off, len);
        buffer.write(b, off, len);
    }

    public void flush() throws IOException {
        if (!buffering) sos.flush();
        // we can't flush our buffer
    }

    public void close() throws IOException {
        if (!buffering) sos.close();
    }

    /* -- ServletOutputStream methods ------------------------------- */

    public void print(String s) throws IOException {
         if (!buffering) sos.print(s);
         byte[] bytes = s.getBytes();
         buffer.write(bytes, 0, bytes.length);
    }
}