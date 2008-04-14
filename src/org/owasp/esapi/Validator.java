/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationAvailabilityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

/**
 * Reference implementation of the IValidator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
 * characters, even in multiple encoding schemes, such as <PRE>&amp;lt;</PRE> or
 * <PRE>%26lt;<PRE> or even <PRE>%25%26lt;</PRE> are disallowed.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.interfaces.IValidator
 */
public class Validator implements org.owasp.esapi.interfaces.IValidator {

	/** The logger. */
	private static final Logger logger = Logger.getLogger("ESAPI", "Validator");
	
	/** anti-Sammy markup verification policy */
	private Policy antiSamyPolicy = null;
	
	/** constants */
	private static final int MAX_CREDIT_CARD_LENGTH = 19;
	private static final int MAX_PARAMETER_NAME_LENGTH = 100;
	private static final int MAX_PARAMETER_VALUE_LENGTH = 10000;
	
	public Validator() {
	}
	

	/**
	 * Returns true if data received from browser is valid. Only URL encoding is
	 * supported. Double encoding is treated as an attack.
	 * 
	 * @param name
	 * @param type
	 * @param value
	 * @return
	 */
	public boolean isValidInput(String context, String type, String value, int maxLength, boolean allowNull) throws IntrusionException  {
		try {
			getValidInput(context, type, value, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 * 
	 * @param name
	 * @param type
	 * @param input
	 * @return
	 * @throws ValidationException
	 */
	public String getValidInput(String context, String type, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {

		try {
			context = ESAPI.encoder().canonicalize( context );
    		String canonical = ESAPI.encoder().canonicalize( input );
    		
    		if (isEmpty(canonical)) {
    			if (allowNull) return null;
       			throw new ValidationException("Bad input", type + " (" + context + ") input to validate was null" );
    		}
    		
    		if (canonical.length() > maxLength) {
    			//TODO - if the length is exceeded by a wide margin, throw IntrusionException?
    			throw new ValidationException("Bad input", context + " input exceedes maxLength by " + (canonical.length()-maxLength) + " characters");
    		}
    		
    		if ( type == null )
    			throw new ValidationException("Bad input", type + " (" + context + ") type to validate against was null" );
    		
    		Pattern p = ((SecurityConfiguration)ESAPI.securityConfiguration()).getValidationPattern( type );
    		if ( p == null )
    			throw new ValidationException("Bad input", type + " (" + context + ") type to validate against not configured in ESAPI.properties" );
    				
    		if ( !p.matcher(canonical).matches() )
    			throw new ValidationException("Bad input", type + " (" + context + "=" + input + ") input did not match type definition " + p.pattern() );
    		
    		// if everything passed, then return the canonical form
    		return canonical;
	    } catch (EncodingException ee) {
	        throw new ValidationException("Internal error", "Error canonicalizing user input", ee);
	    }
	}

	/**
	 * Returns true if input is a valid date according to the specified date format.
	 */
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException {
		try {
			getValidDate(context, input, format, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/*
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#getValidDate(java.lang.String)
	 */
	public Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException {
		try {
			if (isEmpty(input)) {
    			if (allowNull) return null;
       			throw new ValidationException("Invalid date", "(" + context + ") input is required" );
    		}
			
			Date date = format.parse(input);
			return date;
		} catch (Exception e) {
			throw new ValidationException( "Invalid date", "Problem parsing date (" + context + "=" + input + ") ",e );
		}
	}
	
	/*
	 * Returns true if input is "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidSafeHTML(java.lang.String)
	 */
	public boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidSafeHTML(context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/*
	 * Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#getValidSafeHTML(java.lang.String)
	 */
	public String getValidSafeHTML( String context, String input, int maxLength, boolean allowNull ) throws ValidationException, IntrusionException {
		
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException("Bad input", "(" + context + ") input is required" );
		}
		
		if (input.length() > maxLength) {
			//TODO - if the length is exceeded by a wide margin, throw IntrusionException?
			throw new ValidationException("Bad input", context + " input exceedes maxLength by " + (input.length()-maxLength) + " characters");
		}
		
		try {
			if ( antiSamyPolicy == null ) {
				antiSamyPolicy = Policy.getInstance( ESAPI.securityConfiguration().getResourceDirectory() + "antisamy-esapi.xml");
			}
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(input, antiSamyPolicy);
			return(test.getCleanHTML().trim());
		} catch (ScanException e) {
			throw new ValidationException( "Invalid HTML", "Problem parsing HTML (" + context + "=" + input + ") ",e );
		} catch (PolicyException e) {
			throw new ValidationException( "Invalid HTML", "HTML violates policy (" + context + "=" + input + ") ",e );
		}

	}

	/*
	 * Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidCreditCard(java.lang.String)
	 */
	public boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException {
		try {
			getValidCreditCard(context, input, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException("CC# Invalid", "(" + context + ") input is required" );
		}
		
		String canonical = getValidInput(context, "CreditCard", input, MAX_CREDIT_CARD_LENGTH, allowNull);

		// perform Luhn algorithm checking
		StringBuffer digitsOnly = new StringBuffer();
		char c;
		for (int i = 0; i < canonical.length(); i++) {
			c = canonical.charAt(i);
			if (Character.isDigit(c)) {
				digitsOnly.append(c);
			}
		}
	
		int sum = 0;
		int digit = 0;
		int addend = 0;
		boolean timesTwo = false;
	
		for (int i = digitsOnly.length() - 1; i >= 0; i--) {
			digit = Integer.parseInt(digitsOnly.substring(i, i + 1));
			if (timesTwo) {
				addend = digit * 2;
				if (addend > 9) {
					addend -= 9;
				}
			} else {
				addend = digit;
			}
			sum += addend;
			timesTwo = !timesTwo;
		}
	
		int modulus = sum % 10;
		if (modulus != 0) throw new ValidationException("CC# Invalid", "CC# Invalid");
			
		return canonical;

	}

	/**
	 * Returns true if the directory path (not including a filename) is valid.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidDirectoryPath(java.lang.String)
	 */
	public boolean isValidDirectoryPath(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidDirectoryPath(context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Returns a canonicalized and validated directory path as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidDirectoryPath(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		String canonical = "";
		try {
			if (isEmpty(input)) {
				if (allowNull) return null;
	   			throw new ValidationException("Invalid directory name", "(" + context + ") input is required" );
			}
			
			canonical = ESAPI.encoder().canonicalize(input);
			
			// do basic validation
			Pattern directoryNamePattern = ((SecurityConfiguration)ESAPI.securityConfiguration()).getValidationPattern("DirectoryName");
			if ( !directoryNamePattern.matcher(canonical).matches() ) {
				throw new ValidationException("Invalid directory name", "Attempt to use a directory name (" + canonical + ") that violates the global rule in ESAPI.properties (" + directoryNamePattern.pattern() +")" );
			}
			
			// get the canonical path without the drive letter if present
			String cpath = new File(canonical).getCanonicalPath().replaceAll("\\\\", "/");
			String temp = cpath.toLowerCase();
			if (temp.length() >= 2 && temp.charAt(0) >= 'a' && temp.charAt(0) <= 'z' && temp.charAt(1) == ':') {
				cpath = cpath.substring(2);
			}

			// prepare the input without the drive letter if present
			String escaped = canonical.replaceAll("\\\\", "/");
			temp = escaped.toLowerCase();
			if (temp.length() >= 2 && temp.charAt(0) >= 'a' && temp.charAt(0) <= 'z' && temp.charAt(1) == ':') {
				escaped = escaped.substring(2);
			}
			
			// the path is valid if the input matches the canonical path
			if (!escaped.equals(cpath.toLowerCase())) {
				throw new ValidationException("Invalid directory name", "The input path does not match the canonical path (" + canonical + ")" );
			}

		} catch (IOException e) {
			throw new ValidationException("Invalid directory name", "Attempt to use a directory name (" + canonical + ") that does not exist" );
		} catch (EncodingException ee) {
            throw new IntrusionException("Invalid directory", "Exception during directory validation", ee);
		}
		return canonical;
	}


	/**
	 * Returns true if input is a valid file name.
	 * 
	 * FIXME: AAA - need new method getValidFileName that eliminates %00 and other injections.
	 * FIXME: AAA - this method should check for %00 injection too
	 */
	public boolean isValidFileName(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidFileName(context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a canonicalized and validated file name as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidFileName(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
			if (isEmpty(input)) {
				if (allowNull) return null;
				throw new ValidationException("Input is required", "(" + context + ") input is required");
			}
			
			String canonical = "";
			
			// detect path manipulation
			try {
		        canonical = ESAPI.encoder().canonicalize(input);

				// do basic validation
				Pattern fileNamePattern = ((SecurityConfiguration)ESAPI.securityConfiguration()).getValidationPattern("FileName");
				if ( !fileNamePattern.matcher(canonical).matches() ) {
					throw new ValidationException("Invalid filename", "Attempt to use a filename (" + canonical + ") that violates the global rule in ESAPI.properties (" + fileNamePattern.pattern() +")" );
				}
				
				File f = new File(canonical);
				String c = f.getCanonicalPath();
				String cpath = c.substring(c.lastIndexOf(File.separator) + 1);
				if (!input.equals(cpath)) {
					throw new ValidationException("Invalid filename", "Invalid filename (" + canonical + ") doesn't match canonical path (" + cpath + ") and could be an injection attack");
				}
			} catch (IOException e) {
				throw new IntrusionException("Invalid filename", "Exception during filename validation", e);
			} catch (EncodingException ee) {
	            throw new IntrusionException("Invalid filename", "Exception during filename validation", ee);
			}

			// verify extensions
			List extensions = ESAPI.securityConfiguration().getAllowedFileExtensions();
			Iterator i = extensions.iterator();
			while (i.hasNext()) {
				String ext = (String) i.next();
				if (input.toLowerCase().endsWith(ext.toLowerCase())) {
					return canonical;
				}
			}
			throw new IntrusionException("Invalid filename", "Extention does not exist in EASPI.getAllowedFileExtensions list");
	}
	
	/*
	 * Returns true if input is a valid number.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidNumber(java.lang.String)
	 */
	public boolean isValidNumber(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException {
		try {
			getValidNumber( context, input, minValue, maxValue, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a validated number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public Double getValidNumber(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		Double minDoubleValue = new Double(minValue);
		Double maxDoubleValue = new Double(maxValue);
		return getValidDouble( context, input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), allowNull);
	}
	
	/*
	 * Returns true if input is a valid number.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidNumber(java.lang.String)
	 */
	public boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException {
		return isValidDouble( context, input, minValue, maxValue, allowNull );
	}
	
	/**
	 * Returns a validated number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
			throw new ValidationException("Input is required", "Input is required");
		}
		
		try {
			Double d = new Double(Double.parseDouble(input));
			if (d.isInfinite()) throw new ValidationException("Invalid number", "Number is infinite");
			if (d.isNaN()) throw new ValidationException("Invalid number", "Number is not a number");
			if (d.doubleValue() < minValue) throw new ValidationException("Invalid number. Number is too small. Number must be between " + minValue + " and " + maxValue, "Invalid number. Number must be between " + minValue + " and " + maxValue);
			if (d.doubleValue() > maxValue) throw new ValidationException("Invalid number. Number is too large. Number must be between " + minValue + " and " + maxValue, "Invalid number. Number must be between " + minValue + " and " + maxValue);
			
			return d;
		} catch (NumberFormatException e) {
			throw new ValidationException("Invalid number", "Invalid number", e);
		}
	}
	
	/*
	 * Returns true if input is a valid number.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidNumber(java.lang.String)
	 */
	public boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException {
		try {
			getValidInteger( context, input, minValue, maxValue, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns a validated number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
			throw new ValidationException("Input is required", "Input is required");
		}
		
		try {
			int i = Integer.parseInt(input);
			if (i<minValue) throw new ValidationException("Invalid Integer. Integer is too small. Integer must be between " + minValue + " and " + maxValue, "Invalid Integer. Integer must be between " + minValue + " and " + maxValue);
			if (i>maxValue) throw new ValidationException("Invalid Integer. Integer is too large. Integer must be between " + minValue + " and " + maxValue, "Invalid Integer. Integer must be between " + minValue + " and " + maxValue);
			
			return new Integer(i);
		} catch (NumberFormatException e) {
			throw new ValidationException("Invalid Integer", "Invalid Integer", e);
		}
	}
	
	/**
	 * Returns true if input is valid file content.
	 */
	public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException {
		try {
			getValidFileContent( context, input, maxBytes, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Returns validated file content as a byte array. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
			throw new ValidationException("Input is required", "(" + context + ") input is required");
		}
		
		// FIXME: AAA - temporary - what makes file content valid? Maybe need a parameter here?
		long esapiMaxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
		if (input.length > esapiMaxBytes ) throw new ValidationException("Exceeded ESAPI max length", "Exceeded ESAPI max length");
		if (input.length > maxBytes ) throw new ValidationException("Exceeded maxBytes", "Exceeded maxBytes (" + input.length + ")");
		
		return input;
		// FIXME: log something?
	}
	
	/**
	 * Returns true if a file upload has a valid name, path, and content.
	 */
	public boolean isValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException {
		throw new java.lang.UnsupportedOperationException();
	}

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException {
		throw new java.lang.UnsupportedOperationException();
	}

	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * Uses current HTTPRequest saved in EASPI Authenticator
	 */
	public boolean isValidHTTPRequest() throws IntrusionException {
		try {
			assertIsValidHTTPRequest();
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public boolean isValidHTTPRequest(HttpServletRequest request) throws IntrusionException {
		try {
			assertIsValidHTTPRequest(request);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * Uses current HTTPRequest saved in EASPI Authenticator
	 * 
	 */
	public void assertIsValidHTTPRequest() throws ValidationException, IntrusionException {
		HttpServletRequest request = ((Authenticator)ESAPI.authenticator()).getCurrentRequest();
		assertIsValidHTTPRequest(request);
	}
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public void assertIsValidHTTPRequest(HttpServletRequest request) throws ValidationException, IntrusionException {
		
		if (request == null) throw new ValidationException("Invalid HTTPRequest", "HTTPRequest is null");

		Iterator i1 = request.getParameterMap().entrySet().iterator();
		while (i1.hasNext()) {
			Map.Entry entry = (Map.Entry) i1.next();
			String name = (String) entry.getKey();
			if ( !isValidInput( "http", "HTTPParameterName", name, MAX_PARAMETER_NAME_LENGTH, false ) ) {
				// logger.logCritical(Logger.SECURITY, "Parameter name (" + name + ") violates global rule" );
				throw new ValidationException("Invalid HTTPRequest", "Parameter name (" + name + ") violates global rule");
			}

			String[] values = (String[]) entry.getValue();
			Iterator i3 = Arrays.asList(values).iterator();
			// FIXME:Enhance - consider throwing an exception if there are multiple parameters with the same name
			while (i3.hasNext()) {
				String value = (String) i3.next();
				if ( !isValidInput( name, "HTTPParameterValue", value, MAX_PARAMETER_VALUE_LENGTH, true ) ) {
					// logger.logCritical(Logger.SECURITY, "Parameter value (" + name + "=" + value + ") violates global rule" );
					throw new ValidationException("Invalid HTTPRequest", "Parameter value (" + name + "=" + value + ") violates global rule");
				}
			}
		}

		if (request.getCookies() != null) {
			Iterator i2 = Arrays.asList(request.getCookies()).iterator();
			while (i2.hasNext()) {
				Cookie cookie = (Cookie) i2.next();
				String name = cookie.getName();
				if ( !isValidInput( "http", "HTTPCookieName", name, MAX_PARAMETER_NAME_LENGTH, true ) ) {
					// logger.logCritical(Logger.SECURITY, "Cookie name (" + name + ") violates global rule" );
					throw new ValidationException("Invalid HTTPRequest", "Cookie name (" + name + ") violates global rule");
					
				}

				String value = cookie.getValue();
				if ( !isValidInput( name, "HTTPCookieValue", value, MAX_PARAMETER_VALUE_LENGTH, true ) ) {
					// logger.logCritical(Logger.SECURITY, "Cookie value (" + name + "=" + value + ") violates global rule" );
					throw new ValidationException("Invalid HTTPRequest", "Cookie value (" + name + "=" + value + ") violates global rule");
					
				}
			}
		}

		Enumeration e = request.getHeaderNames();
		while (e.hasMoreElements()) {
			String name = (String) e.nextElement();
			if (name != null && !name.equalsIgnoreCase("Cookie")) {
				if ( !isValidInput( "http", "HTTPHeaderName", name, MAX_PARAMETER_NAME_LENGTH, true ) ) {
					// logger.logCritical(Logger.SECURITY, "Header name (" + name + ") violates global rule" );
					throw new ValidationException("Invalid HTTPRequest", "Header name (" + name + ") violates global rule");
					
				}
				
				Enumeration e2 = request.getHeaders(name);
				while (e2.hasMoreElements()) {
					String value = (String) e2.nextElement();
					if ( !isValidInput( name, "HTTPHeaderValue", value, MAX_PARAMETER_VALUE_LENGTH, true ) ) {
						// logger.logCritical(Logger.SECURITY, "Header value (" + name + "=" + value + ") violates global rule" );
						throw new ValidationException("Invalid HTTPRequest", "Header value (" + name + "=" + value + ") violates global rule");
					}
				}
			}
		}
	}

	/*
	 * Returns true if input is a valid list item.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidListItem(java.util.List,
	 *      java.lang.String)
	 */
	public boolean isValidListItem(String context, String input, List list) {
		try {
			getValidListItem( context, input, list);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidListItem(String context, String input, List list) throws ValidationException, IntrusionException {
		if (list.contains(input)) return input;
		
		throw new ValidationException("Item does not exist in List " + context, "Item (" + input + ") does not exist in List " + context);
	}

	/*
	 * Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidParameterSet(java.util.Set,
	 *      java.util.Set, java.util.Set)
	 */
	public boolean isValidHTTPRequestParameterSet(String context, Set requiredNames, Set optionalNames) {
		try {
			assertIsValidHTTPRequestParameterSet( context, requiredNames, optionalNames);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional) throws ValidationException, IntrusionException {
		HttpServletRequest request = ((Authenticator)ESAPI.authenticator()).getCurrentRequest();
		Set actualNames = request.getParameterMap().keySet();
		
		// verify ALL required parameters are present
		Set missing = new HashSet(required);
		missing.removeAll(actualNames);
		if (missing.size() > 0) {
			//TODO - we need to know WHICH element is missing
			throw new ValidationException("Parameter set invalid", "Required element missing");
		}
		
		// verify ONLY optional + required parameters are present
		Set extra = new HashSet(actualNames);
		extra.removeAll(required);
		extra.removeAll(optional);
		if (extra.size() > 0) {
			throw new ValidationException("Parameter set invalid", "Parameters other than optional + required parameters are present");
		}
	}
	
	/**
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII. (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidASCIIFileContent(byte[])
	 */
	public boolean isValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public byte[] getValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
			throw new ValidationException("Input is required", "Input is required");
		}
		
		if (input.length > maxLength) {
			throw new ValidationException("Invalid Input", "Invalid Input. Input exceeded maxLength");
		}
		
		for (int i = 0; i < input.length; i++) {
			if (input[i] < 33 || input[i] > 126) {
				throw new ValidationException("Invalid Input", "Invalid Input. Some characters are not ASCII.");
			}
		}
		return input;
	}

	

	/*
	 * Returns true if input is valid printable ASCII characters (32-126).
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidPrintable(java.lang.String)
	 */
	public boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}
	
	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		String canonical = "";
		try {
    		canonical = ESAPI.encoder().canonicalize(input);
    		getValidPrintable(context, canonical.getBytes(), maxLength, allowNull);
	    } catch (EncodingException ee) {
	        logger.logError(Logger.SECURITY, "Could not canonicalize user input", ee);
	    }
	    return canonical;
	}


	/**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean isValidRedirectLocation(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		// FIXME: ENHANCE - it's too hard to put valid locations in as regex
		return ESAPI.validator().isValidInput(context, "Redirect", input, maxLength, allowNull);
	}


	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidRedirectLocation(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		// FIXME: ENHANCE - it's too hard to put valid locations in as regex
		return ESAPI.validator().getValidInput(context, "Redirect", input, maxLength, allowNull);
	}

	/**
	 * This implementation reads until a newline or the specified number of
	 * characters.
	 * 
	 * @param in
	 *            the in
	 * @param max
	 *            the max
	 * @return the string
	 * @throws ValidationException
	 *             the validation exception
	 * @see org.owasp.esapi.interfaces.IValidator#safeReadLine(java.io.InputStream,
	 *      int)
	 */
	public String safeReadLine(InputStream in, int max) throws ValidationException {
		if (max <= 0)
			throw new ValidationAvailabilityException("Invalid input", "Must read a positive number of bytes from the stream");

		StringBuffer sb = new StringBuffer();
		int count = 0;
		int c;

		// FIXME: AAA - verify this method's behavior exactly matches BufferedReader.readLine()
		// so it can be used as a drop in replacement.
		try {
			while (true) {
				c = in.read();
				if ( c == -1 ) {
					if (sb.length() == 0) return null;
					break;
				}
				if (c == '\n' || c == '\r') break;
				count++;
				if (count > max) {
					throw new ValidationAvailabilityException("Invalid input", "Read more than maximum characters allowed (" + max + ")");
				}
				sb.append((char) c);
			}
			return sb.toString();
		} catch (IOException e) {
			throw new ValidationAvailabilityException("Invalid input", "Problem reading from input stream", e);
		}
	}
	
	/**
	 * helper function to check if a string is empty
	 * 
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private static final boolean isEmpty(String input) {
		if (input==null || input.trim().length() == 0) {
			return true;
		} 
		
		return false;
	}
	
	/**
	 * helper function to check if a byte is empty
	 * 
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private static final boolean isEmpty(byte[] input) {
		if (input==null || input.length == 0) {
			return true;
		} 
		
		return false;
	}
}
