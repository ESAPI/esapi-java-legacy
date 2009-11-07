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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

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

	private static final int FLUSH_BLOCK_SIZE = 1024;
	private ServletOutputStream os;
	private boolean buffering;
	private boolean committed;
	private boolean closed;
	
	private RandomAccessFile out;
	
	public InterceptingServletOutputStream(ServletOutputStream os, boolean buffered) throws FileNotFoundException, IOException {
		super();
		this.os = os;
		this.buffering = buffered;
		this.committed = false;
		this.closed = false;
		
		/*
		 * Creating a RandomAccessFile to keep track of output generated. I made
		 * the prefix and suffix small for less processing. The "oew" is intended
		 * to stand for "OWASP ESAPI WAF" and the "hop" for HTTP output.
		 */
		this.out = new RandomAccessFile ( File.createTempFile("oew", ".hop"), "rw" ); 
	}

	public void reset() throws IOException {
		out.setLength(0L);
	}

	public byte[] getResponseBytes() throws IOException {
		
		byte[] buffer = new byte[(int) out.length()];
		out.seek(0);
		out.read(buffer, 0, (int)out.length());
		out.seek(out.length());
		return buffer;
		
	}

	public void setResponseBytes(byte[] responseBytes) throws IOException {
		
		if ( ! buffering && out.length() > 0 ) {
			throw new IOException("Already committed response because not currently buffering");
		}

		out.setLength(0L);
		out.write(responseBytes);
	}

	public void write(int i) throws IOException {
		if (!buffering) {
			os.write(i);
		}
		out.write(i);
	}

	public void write(byte[] b) throws IOException {
        if (!buffering) {
        	os.write(b, 0, b.length);
        }
        out.write(b, 0, b.length);
    }

	public void write(byte[] b, int off, int len) throws IOException {
        if (!buffering) {
        	os.write(b, off, len);
        }
        out.write(b, off, len);
    }

	public void flush() throws IOException {
		
		if (buffering) {
		
			synchronized(out) {

				out.seek(0);
				
				byte[] buff = new byte[FLUSH_BLOCK_SIZE];
				
				for(int i=0;i<out.length();) {
					
					long currentPos = out.getFilePointer();
					long totalSize = out.length();
					int amountToWrite = FLUSH_BLOCK_SIZE;
					
					if ( (totalSize - currentPos) < FLUSH_BLOCK_SIZE ) {
						amountToWrite = (int) (totalSize - currentPos);
					}
			
					out.read(buff, 0, (int)amountToWrite);
					
					os.write(buff,0,amountToWrite);
					
					i+=amountToWrite;
					
				}
				
				out.setLength(0);
				
			}
		}

	}

	public void commit() throws IOException {
		
		if (!buffering) { // || committed || closed
        	return;
        } else {
        	flush();
        }
		committed = true;
    }

    public void close() throws IOException {
    	
        if (!buffering)  {
        	os.close();
        }
        closed = true;

    }

}
