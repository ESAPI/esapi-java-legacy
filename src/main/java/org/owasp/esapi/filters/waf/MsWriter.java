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

import java.io.CharArrayWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class MsWriter extends PrintWriter {

    private static final char[] NEW_LINE = { '\r', '\n' };

    private boolean buffering = false;

    // TODO this buffer should be replaced with a
    // custom-made one to reduce memory consumption
    private CharArrayWriter buffer;

    private PrintWriter writer;

    public MsWriter(PrintWriter writer) {
        super(writer);
        this.writer = writer;
        buffer = new CharArrayWriter();
    }

    public void setBuffering(boolean buffering) {
        this.buffering = buffering;
    }

    public String toString() {
        return buffer.toString();
    }

    public char[] toCharArray() {
        return buffer.toCharArray();
    }

    public void reset() {
        buffer.reset();
    }

    public void commit() throws IOException {
        if (!buffering) return;
        buffer.writeTo(writer);
        writer.close();
    }

    public void setSuspended(boolean suspended) {
        // TODO
    }

    /* -- PrintWriter methods -------------------------------- */

    public void flush() {
        if (!buffering) super.flush();
        // we can't flush our buffer
    }

    public void close() {
        if (!buffering) super.close();
    }

    public void print(boolean b) {
        if (!buffering) super.print(b);
        write(Boolean.toString(b));
    }

    public void print(char c) {
        if (!buffering) super.print(c);
        buffer.append(c);
    }

    public void print(int i) {
        if (!buffering) super.print(i);
        write(Integer.toString(i));
    }

    public void print(long l) {
        if (!buffering) super.print(l);
        write(Long.toString(l));
    }

    public void print(float f) {
        if (!buffering) super.print(f);
        write(Float.toString(f));
    }

    public void print(double d) {
        if (!buffering) super.print(d);
        write(Double.toString(d));
    }

    public void print(char s[]) {
        if (!buffering) super.print(s);
        buffer.write(s, 0, s.length);
    }

    public void print(String s) {
        if (!buffering) super.print(s);
        write(s);
    }

    public void print(Object obj) {
        if (!buffering) super.print(obj);
        write(obj.toString());
    }

    public void println() {
        if (!buffering) super.println();
        write(NEW_LINE);
    }

    public void println(boolean b) {
        if (!buffering) super.println(b);
        write(Boolean.toString(b));
        write(NEW_LINE);
    }

    public void println(char c) {
        if (!buffering) super.println(c);
        buffer.write(c);
        write(NEW_LINE);
    }

    public void println(int i) {
        if (!buffering) super.println(i);
        write(Integer.toString(i));
        write(NEW_LINE);
    }

    public void println(long l) {
        if (!buffering) super.println(l);
        write(Long.toString(l));
        write(NEW_LINE);
    }

    public void println(float f) {
        if (!buffering) super.println(f);
        write(Float.toString(f));
        write(NEW_LINE);
    }

    public void println(double d) {
        if (!buffering) super.println(d);
        write(Double.toString(d));
        write(NEW_LINE);
    }

    public void println(char c[]) {
        if (!buffering) super.println(c);
        write(c, 0, c.length);
        write(NEW_LINE);
    }

    public void println(String s) {
        if (!buffering) super.println(s);
        write(s);
        write(NEW_LINE);
    }

    public void println(Object o) {
        if (!buffering) super.println(o);
        write(o.toString());
        write(NEW_LINE);
    }

    public void write(int c) {
        if (!buffering) super.write(c);
        buffer.write(c);
    }

    public void write(char buf[], int off, int len) {
        if (!buffering) super.write(buf, off, len);
        buffer.write(buf, off, len);
    }

    public void write(char buf[]) {
	    if (!buffering) super.write(buf);
	    buffer.write(buf, 0, buf.length);
    }

    public void write(String s) {
        if (!buffering) super.write(s);
        buffer.write(s, 0, s.length());
    }

    public void write(String s, int off, int len) {
        if (!buffering) super.write(s, off, len);
        buffer.write(s, off, len);
    }
}