/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2008 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2008
 */
package org.owasp.esapi;

import java.io.File;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.owasp.esapi.errors.ValidationException;

/**
 * Extension to java.io.File to prevent against null byte injections and
 * other unforeseen problems resulting from unprintable characters
 * causing problems in path lookups. This does _not_ prevent against
 * directory traversal attacks.
 */
public class SafeFile extends File {

	private static final long serialVersionUID = 1L;

	public SafeFile(String path) throws ValidationException {
		super(path);
		doFileCheck(path);
	}

	public SafeFile(String parent, String child) throws ValidationException {
		super(parent, child);
		doFileCheck(parent);
		doFileCheck(child);
	}

	public SafeFile(File parent, String child) throws ValidationException {
		super(parent, child);
		doFileCheck(parent.getPath());
		doFileCheck(child);
	}

	public SafeFile(URI uri) throws ValidationException {
		super(uri);
		doFileCheck(uri.toASCIIString());
	}

//  FIXME: much stricter file validation using Validator - but won't work as drop-in replacement as well
//	private void doFileCheck( String path ) throws ValidationException{
//		if ( !ESAPI.validator().isValidFileName( "SafeFile constructor", path ) ) {
//			throw new ValidationException("Invalid file", "File path (" + path + ") is invalid" );
//		}
//	}
	
	Pattern p = Pattern.compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
	
	// check for any percent-encoded characters	
	private void doFileCheck(String path) throws ValidationException {
		Matcher m = p.matcher( path );
		if ( m.find() ) {
			throw new ValidationException( "Invalid file", "File path (" + path + ") contains encoded characters: " + m.group() );
		}
		
		int ch = containsUnprintableCharacters(path);
		if (ch != -1) {
			throw new ValidationException("Invalid file", "File path (" + path + ") contains unprintable character: " + ch);
		}
	}

	private int containsUnprintableCharacters(String s) {
		// FIXME: use Validator.isValidPrintable( s );
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			if (((int) ch) < 32 || ((int) ch) > 126) {
				return (int) ch;
			}
		}
		return -1;
	}

}
