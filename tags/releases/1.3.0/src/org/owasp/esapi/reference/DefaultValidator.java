/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * 
 * @created 2007
 */
package org.owasp.esapi.reference;

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
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationAvailabilityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;

/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization. All double-encoded
 * characters, even in multiple encoding schemes, such as <PRE>&amp;lt;</PRE> or
 * <PRE>%26lt;<PRE> or even <PRE>%25%26lt;</PRE> are disallowed.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim.manico .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 *
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class DefaultValidator implements org.owasp.esapi.Validator {

	/** OWASP AntiSamy markup verification policy */
	private Policy antiSamyPolicy = null;
	
	/** constants */
	private static final int MAX_CREDIT_CARD_LENGTH = 19;
	private static final int MAX_PARAMETER_NAME_LENGTH = 100;
	private static final int MAX_PARAMETER_VALUE_LENGTH = 65535;
	
	public DefaultValidator() {
	}

	/**
	 * Returns true if data received from browser is valid. Only URL encoding is
	 * supported. Double encoding is treated as an attack.
	 * 
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException  {
		try {
			getValidInput( context, input, type, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 * 
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {

		try {
			context = ESAPI.encoder().canonicalize( context );
    		String canonical = ESAPI.encoder().canonicalize( input );

    		if ( type == null || type.length() == 0 ) {
    			throw new RuntimeException( "Validation misconfiguration, specified type to validate against was null: context=" + context + ", type=" + type + "), input=" + input );
    		}
    		
    		if (isEmpty(canonical)) {
    			if (allowNull) return null;
       			throw new ValidationException( context + ": Input required.", "Input required: context=" + context + ", type=" + type + "), input=" + input, context );
    		}

    		if (canonical.length() > maxLength) {
    			throw new ValidationException( context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (canonical.length()-maxLength) + " characters: context=" + context + ", type=" + type + "), input=" + input, context );
    		}

    		Pattern p = ((DefaultSecurityConfiguration)ESAPI.securityConfiguration()).getValidationPattern( type );
    		if ( p == null ) {
    			try {
    				p = Pattern.compile( type );
    			} catch( PatternSyntaxException e ) {
    				throw new RuntimeException( "Validation misconfiguration, specified type to validate against was null: context=" + context + ", type=" + type + "), input=" + input );
    	    	}
    		}

    		if ( !p.matcher(canonical).matches() ) {
    			throw new ValidationException( context + ": Invalid input. Please conform to: " + p.pattern() + " with a maximum length of " + maxLength, "Invalid input: context=" + context + ", type=" + type + "( " + p.pattern() + "), input=" + input, context );
    		}
    		
    		return canonical;
    		
	    } catch (EncodingException e) {
	        throw new ValidationException( context + ": Invalid input. An encoding error occurred.", "Error canonicalizing user input", e, context);
	    }
	}
	
	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 * 
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		
		try {
			return getValidInput(context,  input,  type,  maxLength,  allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}

	/**
	 * Returns true if input is a valid date according to the specified date format.
	 */
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException {
		try {
			getValidDate( context, input, format, allowNull);
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
       			throw new ValidationException( context + ": Input date required", "Input date required: context=" + context + ", input=" + input, context );
    		}
			
			Date date = format.parse(input);
			return date;
		} catch (Exception e) {
			throw new ValidationException( context + ": Invalid date must follow " + format + " format", "Invalid date: context=" + context + ", format=" + format + ", input=" + input, e, context);
		}
	}
	
	/*
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#getValidDate(java.lang.String)
	 */
	public Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidDate(context, input, format, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return null;
	}
	
	/*
	 * Returns true if input is "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidSafeHTML(java.lang.String)
	 */
	public boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		
		try {
			if ( antiSamyPolicy == null ) {
				if (ESAPI.securityConfiguration().getResourceDirectory() == null) {
					
					//load via classpath
			    	ClassLoader loader = getClass().getClassLoader();
			        
			        InputStream in = null;
			        try {
			            in = loader.getResourceAsStream("antisamy-esapi.xml");
			            if (in != null) {
			            	antiSamyPolicy = Policy.getInstance(in);
			            }
			        } catch (Exception e) {
			        	antiSamyPolicy = null;
			            
			        } finally {
			            if (in != null) try { in.close (); } catch (Throwable ignore) {}
			        }
			        
			        if (antiSamyPolicy == null) {
			            throw new IllegalArgumentException ("Can't load antisamy-esapi.xml as a classloader resource");
			        }
			        
				} else {
					//load via fileio
					antiSamyPolicy = Policy.getInstance( ESAPI.securityConfiguration().getResourceDirectory() + "antisamy-esapi.xml");
				}
			}
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(input, antiSamyPolicy);
			return(test.getErrorMessages().size() == 0);
		} catch (Exception e) {
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
   			throw new ValidationException( context + ": Input HTML required", "Input HTML required: context=" + context + ", input=" + input, context );
		}
		
		if (input.length() > maxLength) {
			throw new ValidationException( context + ": Invalid HTML input can not exceed " + maxLength + " characters", context + " input exceedes maxLength by " + (input.length()-maxLength) + " characters", context);
		}
		
		try {
			if ( antiSamyPolicy == null ) {
				if (ESAPI.securityConfiguration().getResourceDirectory() == null) {
					
					//load via classpath
			    	ClassLoader loader = getClass().getClassLoader();
			        
			        InputStream in = null;
			        try {
			            in = loader.getResourceAsStream("antisamy-esapi.xml");
			            if (in != null) {
			            	antiSamyPolicy = Policy.getInstance(in);
			            }
			        } catch (Exception e) {
			        	antiSamyPolicy = null;
			            
			        } finally {
			            if (in != null) try { in.close (); } catch (Throwable ignore) {}
			        }
			        
			        if (antiSamyPolicy == null) {
			            throw new IllegalArgumentException ("Can't load antisamy-esapi.xml as a classloader resource");
			        }
			        
				} else {
					//load via fileio
					antiSamyPolicy = Policy.getInstance( ESAPI.securityConfiguration().getResourceDirectory() + "antisamy-esapi.xml");
				}
			}
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(input, antiSamyPolicy);
			List errors = test.getErrorMessages();
			
			if ( errors.size() > 0 ) {
				// just create new exception to get it logged and intrusion detected
				new ValidationException( "Invalid HTML input: context=" + context, "Invalid HTML input: context=" + context + ", errors=" + errors, context );
			}
			
			return(test.getCleanHTML().trim());
		
		} catch (ScanException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input: context=" + context + " error=" + e.getMessage(), e, context );
		
		} catch (PolicyException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " error=" + e.getMessage(), e, context );
		}
	}
	
	/**
	 * ValidationErrorList variant of getValidSafeHTML
	 */
	public String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidSafeHTML(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}

	/*
	 * Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidCreditCard(java.lang.String)
	 */
	public boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException {
		try {
			getValidCreditCard( context, input, allowNull);
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
   			throw new ValidationException( context + ": Input credit card required", "Input credit card required: context=" + context + ", input=" + input, context );
		}
		
		String canonical = getValidInput( context, input, "CreditCard", MAX_CREDIT_CARD_LENGTH, allowNull);

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
		if (modulus != 0) throw new ValidationException( context + ": Invalid credit card input", "Invalid credit card input: context=" + context, context );
			
		return canonical;

	}
	
	/**
	 * ValidationErrorList variant of getValidCreditCard
	 */
	public String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidCreditCard(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}

	/**
	 * Returns true if the directory path (not including a filename) is valid.
	 * 
	 * @see org.owasp.esapi.Validator#isValidDirectoryPath(java.lang.String)
	 */
	public boolean isValidDirectoryPath(String context, String input, boolean allowNull) throws IntrusionException {
		try {
			getValidDirectoryPath( context, input, allowNull);
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
	public String getValidDirectoryPath(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		try {
			if (isEmpty(input)) {
				if (allowNull) return null;
       			throw new ValidationException( context + ": Input directory path required", "Input directory path required: context=" + context + ", input=" + input, context );
			}
						
			// do basic validation
			String canonical = getValidInput( context, input, "DirectoryName", 255, false);
			
			// get the canonical path without the drive letter if present
			String cpath = new File(canonical).getCanonicalPath().replaceAll( "\\\\", "/");
			String temp = cpath.toLowerCase();
			if (temp.length() >= 2 && temp.charAt(0) >= 'a' && temp.charAt(0) <= 'z' && temp.charAt(1) == ':') {
				cpath = cpath.substring(2);
			}

			// prepare the input without the drive letter if present
			String escaped = canonical.replaceAll( "\\\\", "/");
			temp = escaped.toLowerCase();
			if (temp.length() >= 2 && temp.charAt(0) >= 'a' && temp.charAt(0) <= 'z' && temp.charAt(1) == ':') {
				escaped = escaped.substring(2);
			}
			
			// the path is valid if the input matches the canonical path
			if (!escaped.equals(cpath.toLowerCase())) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context );
			}
			return canonical; 
		} catch (IOException e) {
			throw new ValidationException( context + ": Invalid directory name", "Invalid directory name does not exist: context=" + context + ", input=" + input, e, context );
		}
	}
	
	/**
	 * ValidationErrorList variant of getValidDirectoryPath
	 */
	public String getValidDirectoryPath(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidDirectoryPath(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}


	/**
	 * Returns true if input is a valid file name.
	 */
	public boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException {
		try {
			getValidFileName( context, input, allowNull);
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
	public String getValidFileName(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		String canonical = "";
		// detect path manipulation
		try {
			if (isEmpty(input)) {
				if (allowNull) return null;
	   			throw new ValidationException( context + ": Input file name required", "Input required: context=" + context + ", input=" + input, context );
			}
			
			// do basic validation
	        canonical = ESAPI.encoder().canonicalize(input);
	        getValidInput( context, input, "FileName", 255, true );
			
			File f = new File(canonical);
			String c = f.getCanonicalPath();
			String cpath = c.substring(c.lastIndexOf(File.separator) + 1);

			
			// the path is valid if the input matches the canonical path
			if (!input.equals(cpath.toLowerCase())) {
				throw new ValidationException( context + ": Invalid file name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context );
			}

		} catch (IOException e) {
			throw new ValidationException( context + ": Invalid file name", "Invalid file name does not exist: context=" + context + ", canonical=" + canonical, e, context );
		} catch (EncodingException ee) {
            throw new IntrusionException( context + ": Invalid file name", "Invalid file name: context=" + context + ", canonical=" + canonical, ee );
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
		throw new ValidationException( context + ": Invalid file name does not have valid extension ( "+ESAPI.securityConfiguration().getAllowedFileExtensions()+")", "Invalid file name does not have valid extension ( "+ESAPI.securityConfiguration().getAllowedFileExtensions()+"): context=" + context+", input=" + input, context );
	}
	
	/**
	 * Returns a canonicalized and validated file name as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidFileName(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidFileName(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}
	
	/*
	 * Returns true if input is a valid number.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidNumber(java.lang.String)
	 */
	public boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException {
		try {
			getValidNumber(context, input, minValue, maxValue, allowNull);
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
	public Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		Double minDoubleValue = new Double(minValue);
		Double maxDoubleValue = new Double(maxValue);
		return getValidDouble(context, input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), allowNull);
	}
	
	public Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidNumber(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		
		//not sure what to return on error
		return new Double(0);
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
		if (minValue > maxValue) {
			//should this be a RunTime?
			throw new ValidationException( context + ": Invalid double input: context", "Validation parameter error for double: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ") for " + context, context );
		}
		
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException( context + ": Input required: context", "Input required: context=" + context + ", input=" + input, context );
		}
		
		try {
			Double d = new Double(Double.parseDouble(input));
			if (d.isInfinite()) throw new ValidationException( "Invalid double input: context=" + context, "Invalid double input is infinite: context=" + context + ", input=" + input, context );
			if (d.isNaN()) throw new ValidationException( "Invalid double input: context=" + context, "Invalid double input is infinite: context=" + context + ", input=" + input, context );
			if (d.doubleValue() < minValue) throw new ValidationException( "Invalid double input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid double input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
			if (d.doubleValue() > maxValue) throw new ValidationException( "Invalid double input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid double input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
			
			return d;
		} catch (NumberFormatException e) {
			throw new ValidationException( context + ": Invalid double input", "Invalid double input format: context=" + context + ", input=" + input, e, context);
		}
	}
	
	public Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidDouble(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		
		//not sure what to return on error
		return new Double(0);
	}
	
	/*
	 * Returns true if input is a valid number.
	 * 
	 * @see org.owasp.esapi.interfaces.IValidator#isValidInteger(java.lang.String)
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
		if (minValue > maxValue) {
			//should this be a RunTime?
			throw new ValidationException( context + ": Invalid Integer", "Validation parameter error for double: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ") for " + context, context );
		}
		
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException( context + ": Input required", "Input required: context=" + context + ", input=" + input, context );
		}
		
		try {
			int i = Integer.parseInt(input);
			if (i < minValue || i > maxValue ) throw new ValidationException( context + ": Invalid Integer. Value must be between " + minValue + " and " + maxValue, "Invalid int input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
			return new Integer(i);
		} catch (NumberFormatException e) {
			throw new ValidationException( context + ": Invalid integer input", "Invalid int input: context=" + context + ", input=" + input, e, context );
		}
	}
	
	public Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidInteger(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		
		//not sure what to return on error
		return new Integer(0);
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
   			throw new ValidationException( context + ": Input required", "Input required: context=" + context + ", input=" + input, context );
		}
		
		long esapiMaxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
		if (input.length > esapiMaxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + esapiMaxBytes + " bytes", "Exceeded ESAPI max length", context );
		if (input.length > maxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + maxBytes + " bytes", "Exceeded maxBytes ( " + input.length + ")", context );
		
		return input;
	}
	
	public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidFileContent(context, input, maxBytes, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		
		//not sure what to return on error
		return input;
	}
	
	/**
	 * Returns true if a file upload has a valid name, path, and content.
	 */
	public boolean isValidFileUpload(String context, String directorypath, String filename, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException {
		return( isValidFileName( context, filename, allowNull ) &&
				isValidDirectoryPath( context, directorypath, allowNull ) &&
				isValidFileContent( context, content, maxBytes, allowNull ) );
	}

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public void assertValidFileUpload(String context, String directorypath, String filename, byte[] content, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException {
		getValidFileName( context, filename, allowNull );
		getValidDirectoryPath( context, directorypath, allowNull );
		getValidFileContent( context, content, maxBytes, allowNull );
	}
	

	/**
	 * ValidationErrorList variant of assertValidFileUpload
	 */
	public void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errors) 
		throws IntrusionException {
		try {
			assertValidFileUpload(context, filepath, filename, content, maxBytes, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
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
		HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
		assertIsValidHTTPRequest(request);
	}
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	private void assertIsValidHTTPRequest(HttpServletRequest request) throws ValidationException, IntrusionException {
		
		if (request == null) {
   			throw new ValidationException( "Input required: HTTP request is null", "Input required: HTTP request is null" );
		}

		if ( !request.getMethod().equals( "GET") && !request.getMethod().equals("POST") ) {
   			throw new IntrusionException( "Bad HTTP method received", "Bad HTTP method received: " + request.getMethod() );
		}
		
		Iterator i1 = request.getParameterMap().entrySet().iterator();
		while (i1.hasNext()) {
			Map.Entry entry = (Map.Entry) i1.next();
			String name = (String) entry.getKey();
			getValidInput( "HTTP request parameter: " + name, name, "HTTPParameterName", MAX_PARAMETER_NAME_LENGTH, false );
			String[] values = (String[]) entry.getValue();
			Iterator i3 = Arrays.asList(values).iterator();
			while (i3.hasNext()) {
				String value = (String) i3.next();
				getValidInput( "HTTP request parameter: " + name, value, "HTTPParameterValue", MAX_PARAMETER_VALUE_LENGTH, true );
			}
		}

		if (request.getCookies() != null) {
			Iterator i2 = Arrays.asList(request.getCookies()).iterator();
			while (i2.hasNext()) {
				Cookie cookie = (Cookie) i2.next();
				String name = cookie.getName();
				getValidInput( "HTTP request cookie: " + name, name, "HTTPCookieName", MAX_PARAMETER_NAME_LENGTH, true );
				String value = cookie.getValue();
				getValidInput( "HTTP request cookie: " + name, value, "HTTPCookieValue", MAX_PARAMETER_VALUE_LENGTH, true );
			}
		}

		Enumeration e = request.getHeaderNames();
		while (e.hasMoreElements()) {
			String name = (String) e.nextElement();
			if (name != null && !name.equalsIgnoreCase( "Cookie")) {
				getValidInput( "HTTP request header: " + name, name, "HTTPHeaderName", MAX_PARAMETER_NAME_LENGTH, true );				
				Enumeration e2 = request.getHeaders(name);
				while (e2.hasMoreElements()) {
					String value = (String) e2.nextElement();
					getValidInput( "HTTP request header: " + name, value, "HTTPHeaderValue", MAX_PARAMETER_VALUE_LENGTH, true );
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
		throw new ValidationException( context + ": Invalid list item", "Invalid list item: context=" + context + ", input=" + input, context );
	}
	

	/**
	 * ValidationErrorList variant of getValidListItem
	 */
	public String getValidListItem(String context, String input, List list, ValidationErrorList errors) throws IntrusionException {
		
		try {
			return getValidListItem(context, input, list);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
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
		HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
		Set actualNames = request.getParameterMap().keySet();
		
		// verify ALL required parameters are present
		Set missing = new HashSet(required);
		missing.removeAll(actualNames);
		if (missing.size() > 0) {
			throw new ValidationException( context + ": Invalid HTTP request missing parameters", "Invalid HTTP request missing parameters " + missing + ": context=" + context, context );
		}
		
		// verify ONLY optional + required parameters are present
		Set extra = new HashSet(actualNames);
		extra.removeAll(required);
		extra.removeAll(optional);
		if (extra.size() > 0) {
			throw new ValidationException( context + ": Invalid HTTP request extra parameters " + extra, "Invalid HTTP request extra parameters " + extra + ": context=" + context, context );
		}
	}
	
	/**
	 * ValidationErrorList variant of assertIsValidHTTPRequestParameterSet
	 */
	public void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional, ValidationErrorList errors) throws IntrusionException {
		try {
			assertIsValidHTTPRequestParameterSet(context, required, optional);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
	}
	
	/**
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII. (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.Validator#isValidASCIIFileContent(byte[])
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
   			throw new ValidationException(context + ": Input bytes required", "Input bytes required: HTTP request is null", context );
		}

		if (input.length > maxLength) {
			throw new ValidationException(context + ": Input bytes can not exceed " + maxLength + " bytes", "Input exceeds maximum allowed length of " + maxLength + " by " + (input.length-maxLength) + " bytes: context=" + context + ", input=" + input, context);
		}
		
		for (int i = 0; i < input.length; i++) {
			if (input[i] < 33 || input[i] > 126) {
				throw new ValidationException(context + ": Invalid input bytes: context=" + context, "Invalid non-ASCII input bytes, context=" + context + ", input=" + input, context);
			}
		}
		return input;
	}
	
	/**
	 * ValidationErrorList variant of getValidPrintable
	 */
	public byte[] getValidPrintable(String context, byte[] input,int maxLength, boolean allowNull, ValidationErrorList errors)
		throws IntrusionException {
	
		try {
			return getValidPrintable(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
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
    		return new String( getValidPrintable( context, canonical.getBytes(), maxLength, allowNull) );
	    } catch (EncodingException e) {
	        throw new ValidationException( context + ": Invalid printable input", "Invalid encoding of printable input, context=" + context + ", input=" + input, e, context);
	    }
	}
	
	/**
	 * ValidationErrorList variant of getValidPrintable
	 */
	public String getValidPrintable(String context, String input,int maxLength, boolean allowNull, ValidationErrorList errors)
		throws IntrusionException {
	
		try {
			return getValidPrintable(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
	}


	/**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean isValidRedirectLocation(String context, String input, boolean allowNull) throws IntrusionException {
		return ESAPI.validator().isValidInput( context, input, "Redirect", 512, allowNull);
	}


	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	public String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		return ESAPI.validator().getValidInput( context, input, "Redirect", 512, allowNull);
	}
	
	/**
	 * ValidationErrorList variant of getValidRedirectLocation
	 */
	public String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidRedirectLocation(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		return input;
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
	 * @see org.owasp.esapi.Validator#safeReadLine(java.io.InputStream,
	 *      int)
	 */
	public String safeReadLine(InputStream in, int max) throws ValidationException {
		if (max <= 0)
			throw new ValidationAvailabilityException( "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream");

		StringBuffer sb = new StringBuffer();
		int count = 0;
		int c;

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
					throw new ValidationAvailabilityException( "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" + max + ")");
				}
				sb.append((char) c);
			}
			return sb.toString();
		} catch (IOException e) {
			throw new ValidationAvailabilityException( "Invalid input", "Invalid readLine. Problem reading from input stream", e);
		}
	}
	
	/**
	 * Helper function to check if a String is empty
	 * 
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private final boolean isEmpty(String input) {
		return (input==null || input.trim().length() == 0);
	}
	
	/**
	 * Helper function to check if a byte array is empty
	 * 
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private final boolean isEmpty(byte[] input) {
		return (input==null || input.length == 0);
	}
}
