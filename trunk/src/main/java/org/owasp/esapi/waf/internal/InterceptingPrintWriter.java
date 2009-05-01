package org.owasp.esapi.waf.internal;

import java.io.PrintWriter;
import java.io.Writer;
import java.util.Locale;

public class InterceptingPrintWriter extends PrintWriter {

	public InterceptingPrintWriter(Writer out) {
		super(out);
	}

	public PrintWriter append(char c) {
		return super.append(c);
	}

	public PrintWriter append(CharSequence csq, int start, int end) {
		return super.append(csq, start, end);
	}

	public PrintWriter append(CharSequence csq) {
		return super.append(csq);
	}

	public boolean checkError() {
		return super.checkError();
	}

	protected void clearError() {
		super.clearError();
	}

	public void close() {
		super.close();
	}

	public void flush() {
		super.flush();
	}

	public PrintWriter format(Locale l, String format, Object... args) {
		return super.format(l, format, args);
	}

	public PrintWriter format(String format, Object... args) {
		return super.format(format, args);
	}

	public void print(boolean b) {
		super.print(b);
	}

	public void print(char c) {
		super.print(c);
	}

	public void print(char[] s) {
		super.print(s);
	}

	public void print(double d) {
		super.print(d);
	}

	public void print(float f) {
		super.print(f);
	}

	public void print(int i) {
		super.print(i);
	}

	public void print(long l) {
		super.print(l);
	}

	public void print(Object obj) {
		super.print(obj);
	}

	public void print(String s) {
		super.print(s);
	}

	public PrintWriter printf(Locale l, String format, Object... args) {
		return super.printf(l, format, args);
	}

	public PrintWriter printf(String format, Object... args) {
		return super.printf(format, args);
	}

	public void println() {
		super.println();
	}

	public void println(boolean x) {
		super.println(x);
	}

	public void println(char x) {
		super.println(x);
	}

	public void println(char[] x) {
		super.println(x);
	}

	public void println(double x) {
		super.println(x);
	}

	public void println(float x) {
		super.println(x);
	}

	public void println(int x) {
		super.println(x);
	}

	public void println(long x) {
		super.println(x);
	}

	public void println(Object x) {
		super.println(x);
	}

	public void println(String x) {
		super.println(x);
	}

	protected void setError() {
		super.setError();
	}

	public void write(char[] buf, int off, int len) {
		super.write(buf, off, len);
	}

	public void write(char[] buf) {
		super.write(buf);
	}

	public void write(int c) {
		super.write(c);
	}

	public void write(String s, int off, int len) {
		super.write(s, off, len);
	}

	public void write(String s) {
		super.write(s);
	}

}
