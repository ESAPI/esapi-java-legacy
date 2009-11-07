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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.apache.commons.io.IOUtils;
import org.owasp.esapi.waf.UploadTooLargeException;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;

public class InterceptingHTTPServletRequest extends HttpServletRequestWrapper {

	private Vector<Parameter> allParameters;
	private Vector<String> allParameterNames;
	private static int CHUNKED_BUFFER_SIZE = 1024;
	
	private boolean isMultipart = false;
	private RandomAccessFile requestBody;
	private RAFInputStream is;
	
	public ServletInputStream getInputStream() throws IOException {
		
		if ( isMultipart ) {
			return is;	
		} else {
			return super.getInputStream();
		}
        
    }
	
	public BufferedReader getReader() throws IOException {
        String enc = getCharacterEncoding();
        if(enc == null) enc = "UTF-8";
        return new BufferedReader(new InputStreamReader(getInputStream(), enc));
    }
	
	public InterceptingHTTPServletRequest(HttpServletRequest request) throws UploadTooLargeException, FileUploadException, IOException {

		super(request);

		allParameters = new Vector<Parameter>();
		allParameterNames = new Vector<String>();


		/*
		 * Get all the regular parameters.
		 */

		Enumeration e = request.getParameterNames();

		while(e.hasMoreElements()) {
			String param = (String)e.nextElement();
			allParameters.add(new Parameter(param,request.getParameter(param),false));
			allParameterNames.add(param);
		}


		/*
		 * Get all the multipart fields.
		 */

		isMultipart = ServletFileUpload.isMultipartContent(request);

		if ( isMultipart ) {

			requestBody = new RandomAccessFile( File.createTempFile("oew","mpc"), "rw");
	    	
	    	byte buffer[] = new byte[CHUNKED_BUFFER_SIZE];

	    	long size = 0;
	    	int len = 0;

	    	while ( len != -1 && size <= Integer.MAX_VALUE) {
	    		len = request.getInputStream().read(buffer, 0, CHUNKED_BUFFER_SIZE);
	    		if ( len != -1 ) {
	    			size += len;
	    			requestBody.write(buffer,0,len);	
	    		}
	    	}
			
	    	is = new RAFInputStream(requestBody);
	    	
			ServletFileUpload sfu = new ServletFileUpload();
			FileItemIterator iter = sfu.getItemIterator(this);

			while(iter.hasNext()) {
				FileItemStream item = iter.next();
				String name = item.getFieldName();
				InputStream stream = item.openStream();

				/*
				 * If this is a regular form field, add it to our
				 * parameter collection.
				 */

				if (item.isFormField()) {

					String value = Streams.asString(stream);

					allParameters.add(new Parameter(name,value,true));
			    	allParameterNames.add(name);

			    } else {
			    	/*
			    	 * This is a multipart content that is not a
			    	 * regular form field. Nothing to do here.
			    	 */
			    	
			    }

			}
			
			requestBody.seek(0);
			
		}

	}

	public String getDictionaryParameter(String s) {

		for(int i=0;i<allParameters.size();i++) {
			Parameter p = allParameters.get(i);
			if ( p.getName().equals(s) ) {
				return p.getValue();
			}
		}
		
		return null;
	}

	public Enumeration getDictionaryParameterNames() {
		return allParameterNames.elements();
	}
	
	
	private class RAFInputStream extends ServletInputStream {
		
		RandomAccessFile raf;
		
		public RAFInputStream(RandomAccessFile raf) throws IOException {
			this.raf = raf;
			this.raf.seek(0);
		}

		public int read() throws IOException {
			return raf.read();
		}
		
		public synchronized void reset() throws IOException {
			raf.seek(0);
		}
	}
	
}
