/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.internal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.ServletOutputStream;

/*
 * This class was inspired by ModSecurity for Java by Ivan Ristic. We hook
 * the response stream and queue up all outbound data so that we can apply
 * egress rules. For efficiency, we decide off the bat if we need to buffer.
 *
 * If not, we just forward everything through, otherwise we write data to our
 * byte stream that we will eventually forward en totale to the user agent.
 */

public class InterceptingServletOutputStream extends ServletOutputStream {

	private ServletOutputStream os;
	private ByteArrayOutputStream bos;
	private boolean buffering;

	public InterceptingServletOutputStream(ServletOutputStream os, boolean buffered) {
		super();
		this.os = os;
		this.buffering = buffered;
		this.bos = new ByteArrayOutputStream();
	}

	public void reset() {
		bos.reset();
	}

	public byte[] getResponseBytes() {
		return bos.toByteArray();
	}

	public void setResponseBytes(byte[] responseBytes) throws IOException {
		if ( ! buffering && bos.toByteArray().length > 0 ) {
			throw new IOException("Already committed response because not currently buffering");
		}

		bos = new ByteArrayOutputStream();
		bos.write(responseBytes);
	}

	public void write(int i) throws IOException {
		if (!buffering) {
			os.write(i);
		}
		bos.write(i);
	}

	public void write(byte[] b) throws IOException {
        if (!buffering) {
        	os.write(b, 0, b.length);
        }
        bos.write(b, 0, b.length);
    }

	public void write(byte[] b, int off, int len) throws IOException {
        if (!buffering) {
        	os.write(b, off, len);
        }
        bos.write(b, off, len);
    }

	public void flush() throws IOException {
		if (buffering) {
			os.write(bos.toByteArray());
		}

		bos.reset();
	}

	public void commit() throws IOException {
		if (!buffering) {
        	return;
        }
        bos.writeTo(os);
        os.close();
        bos.close();
    }

    public void close() throws IOException {
        if (!buffering)  {
        	os.close();
        }
    }

}
