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
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.fileupload.FileItemIterator;
import org.apache.commons.fileupload.FileItemStream;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.fileupload.util.Streams;
import org.owasp.esapi.waf.UploadTooLargeException;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;

public class InterceptingHTTPServletRequest extends HttpServletRequestWrapper {

	private Vector<Parameter> allParameters;
	private Vector<String> allParameterNames;
	private static int CHUNKED_BUFFER_SIZE = 1024;

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

		boolean isMultipart = ServletFileUpload.isMultipartContent(request);

		if ( isMultipart ) {

			request.getInputStream().mark(0);

			ServletFileUpload sfu = new ServletFileUpload();
			FileItemIterator iter = sfu.getItemIterator(request);

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
			    	 * regular form field. Our job is to stream it
			    	 * to make sure it's not too big.
			    	 */
			    	
			    	//oew=owasp esapi waf, mpc=multipart content

			    	RandomAccessFile raf = new RandomAccessFile( File.createTempFile("oew-"+item.getFieldName(),"mpc"), "r");
			    	
			    	byte buffer[] = new byte[CHUNKED_BUFFER_SIZE];

			    	int size = 0;
			    	int len = 0;

			    	while ( len != -1 && size <= AppGuardianConfiguration.MAX_FILE_SIZE ) {
			    		len = stream.read(buffer, 0, CHUNKED_BUFFER_SIZE);
			    		if ( len != -1 ) {
			    			size += len;
				    		raf.write(buffer,0,len);	
			    		}
			    	}

		    		if ( size > AppGuardianConfiguration.MAX_FILE_SIZE) {
		    			throw new UploadTooLargeException("param: " + name);
		    		}
			    }

			}
			
			request.getInputStream().reset();
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

}
