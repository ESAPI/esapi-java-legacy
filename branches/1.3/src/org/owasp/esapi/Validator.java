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
 * @created 2007
 */
package org.owasp.esapi;

import java.io.InputStream;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;


/**
 * The Validator interface defines a set of methods for canonicalizing and
 * validating untrusted input. Implementors should feel free to extend this
 * interface to accommodate their own data formats. Rather than throw exceptions,
 * this interface returns boolean results because not all validation problems
 * are security issues. Boolean returns allow developers to handle both valid
 * and invalid results more cleanly than exceptions.
 * <P>
 * <img src="doc-files/Validator.jpg" height="600">
 * <P>
 * Implementations must adopt a "whitelist" approach to validation where a
 * specific pattern or character set is matched. "Blacklist" approaches that
 * attempt to identify the invalid or disallowed characters are much more likely
 * to allow a bypass with encoding or other tricks.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Validator {

	/**
	 * Returns true if input is valid according to the specified type. The type parameter must be the name 
	 * of a defined type in the ESAPI configuration or a valid regular expression. Implementers should take 
	 * care to make the type storage simple to understand and configure.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param type 
	 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if the input is valid based on the rules set by 'type'
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param type 
	 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return The canonicalized user input.
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException.  Instead of
	 * throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param type 
	 * 		The regular expression name that maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return The canonicalized user input.
	 * 
	 * @throws IntrusionException
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if input is a valid date according to the specified date format.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param format 
	 * 		Required formatting of date inputted.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException. 
	 * 
	 * @return true, if input is a valid date according to the format specified by 'format'
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param format 
	 * 		Required formatting of date inputted.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return A valid date as a Date
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException;	
	
	/**
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException and store it inside of 
	 * the errorList argument, and input that is clearly an attack will generate a descriptive IntrusionException.  Instead of
	 * throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param format 
	 * 		Required formatting of date inputted.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A valid date as a Date
	 * 
	 * @throws IntrusionException
	 */
	Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;	
	
	/**
	 * Returns true if input is "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if input is valid safe HTML
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return Valid safe HTML
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem. Instead of
	 * throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param maxLength 
	 * 		The maximum post-canonicalized String length allowed.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return Valid safe HTML
	 * 
	 * @throws IntrusionException
	 */
	String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if input is a valid credit card number
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual user input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return A valid credit card number
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException 
	 */
	String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A valid credit card number
	 * 
	 * @throws IntrusionException
	 */
	String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if input is a valid directory path.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if input is a valid directory path
	 * 
	 * @throws IntrusionException 
	 */
	boolean isValidDirectoryPath(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated directory path as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return A valid directory path
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidDirectoryPath(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated directory path as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 *  
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
     * 
     * @return A valid directory path
     * 
     * @throws IntrusionException
	 */
	String getValidDirectoryPath(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	
	/**
	 * Returns true if input is a valid file name.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return true, if input is a valid file name
     * 
     * @throws IntrusionException
	 */
	boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.properties". Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return A valid file name
     * 
     * @throws ValidationException
     * @throws IntrusionException
	 */
	String getValidFileName(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated file name as a String. Implementors should check for allowed file extensions here, as well as allowed file name characters, as declared in "ESAPI.properties".  Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
     * 
     * @return A valid file name
     * 
     * @throws IntrusionException
	 */
	String getValidFileName(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
		
	/**
	 * Returns true if input is a valid number within the range of minValue to maxValue.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return true, if input is a valid number
     * 
     * @throws IntrusionException
	 */
	boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated number as a double within the range of minValue to maxValue. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated number as a double.
     * 
     * @throws ValidationException
     * @throws IntrusionException
	 */
	Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a validated number as a double within the range of minValue to maxValue. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param minValue 
	 * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A validated number as a double.
     * 
     * @throws IntrusionException
	 */
	Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns true if input is a valid integer within the range of minValue to maxValue.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return true, if input is a valid integer
     * 
     * @throws IntrusionException
	 */
	boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated integer. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated number as an integer.
     * 
     * @throws ValidationException
     * @throws IntrusionException
	 */
	Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a validated integer. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param minValue 
	 * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A validated number as an integer.
     * 
     * @throws IntrusionException
	 */
	Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
		
	/**
	 * Returns true if input is a valid double within the range of minValue to maxValue.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return true, if input is a valid double.
     * 
     * @throws IntrusionException
	 * 
	 */
	boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		The actual input data to validate.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * @param minValue 
     * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * 
     * @return A validated real number as a double.
     * 
     * @throws ValidationException
     * @throws IntrusionException
	 */
	Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param minValue 
	 * 		Lowest legal value for input.
     * @param maxValue 
     * 		Highest legal value for input.
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A validated real number as a double.
     * 
     * @throws IntrusionException
	 */
	Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns true if input is valid file content.  This is a good place to check for max file size, allowed character sets, and do virus scans.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param maxBytes 
	 * 		The maximum number of bytes allowed in a legal file.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if input contains valid file content.
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param maxBytes 
	 * 		The maximum number of bytes allowed in a legal file.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return A byte array containing valid file content.
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns validated file content as a byte array. This is a good place to check for max file size, allowed character sets, and do virus scans.  Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The actual input data to validate.
	 * @param maxBytes 
	 * 		The maximum number of bytes allowed in a legal file.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context.
	 * 
	 * @return A byte array containing valid file content.
	 * 
	 * @throws IntrusionException
	 */
	byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns true if a file upload has a valid name, path, and content.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param filepath 
	 * 		The file path of the uploaded file.
	 * @param filename 
	 * 		The filename of the uploaded file
	 * @param content 
	 * 		A byte array containing the content of the uploaded file.
	 * @param maxBytes 
	 * 		The max number of bytes allowed for a legal file upload.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if a file upload has a valid name, path, and content.
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param filepath 
	 * 		The file path of the uploaded file.
	 * @param filename 
	 * 		The filename of the uploaded file
	 * @param content 
	 * 		A byte array containing the content of the uploaded file.
	 * @param maxBytes 
	 * 		The max number of bytes allowed for a legal file upload.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param filepath 
	 * 		The file path of the uploaded file.
	 * @param filename 
	 * 		The filename of the uploaded file
	 * @param content 
	 * 		A byte array containing the content of the uploaded file.
	 * @param maxBytes 
	 * 		The max number of bytes allowed for a legal file upload.
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @throws IntrusionException
	 */
	void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
     * Validate the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
     * characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.
     * 
     * @return true, if is a valid HTTP request
     * 
     * @throws IntrusionException
     */
	boolean isValidHTTPRequest() throws IntrusionException;
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	void assertIsValidHTTPRequest() throws ValidationException, IntrusionException;
	
	/**
	 * Returns true if input is a valid list item.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The value to search 'list' for.
	 * @param list 
	 * 		The list to search for 'input'.
	 * 
	 * @return true, if 'input' was found in 'list'.
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidListItem(String context, String input, List list) throws IntrusionException;

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The value to search 'list' for.
	 * @param list 
	 * 		The list to search for 'input'.
	 * 
	 * @return The list item that exactly matches the canonicalized input.
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidListItem(String context, String input, List list) throws ValidationException, IntrusionException;

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		The value to search 'list' for.
	 * @param list 
	 * 		The list to search for 'input'.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return The list item that exactly matches the canonicalized input.
	 * 
	 * @throws IntrusionException
	 */
	String getValidListItem(String context, String input, List list, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param required 
	 * 		parameters that are required to be in HTTP request 
	 * @param optional 
	 * 		additional parameters that may be in HTTP request
	 * 
	 * @return true, if all required parameters are in HTTP request and only optional parameters in addition.  Returns false if parameters are found in HTTP request that are not in either set (required or optional), or if any required parameters are missing from request.
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidHTTPRequestParameterSet(String context, Set required, Set optional) throws IntrusionException;

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param required 
	 * 		parameters that are required to be in HTTP request
	 * @param optional 
	 * 		additional parameters that may be in HTTP request
	 * 
	 * @throws ValidationException
	 * @throws IntrusionException 
	 */
	void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional) throws ValidationException, IntrusionException;
	
	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param required 
	 * 		parameters that are required to be in HTTP request
	 * @param optional 
	 * 		additional parameters that may be in HTTP request
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @throws IntrusionException
	 */
	void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if input contains only valid printable ASCII characters.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		data to be checked for validity
	 * @param maxLength 
	 * 		Maximum number of bytes stored in 'input'
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if 'input' is less than maxLength and contains only valid, printable characters
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 *  @param context 
	 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 *  @param input 
	 *  		data to be returned as valid and printable
	 *  @param maxLength 
	 *  		Maximum number of bytes stored in 'input'
	 *  @param allowNull 
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *  
	 *  @return a byte array containing only printable characters, made up of data from 'input'
	 *  
	 *  @throws ValidationException
	 */
	byte[] getValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws ValidationException;

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		data to be returned as valid and printable
	 * @param maxLength 
	 * 		Maximum number of bytes stored in 'input'
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return a byte array containing only printable characters, made up of data from 'input'
	 * 
	 * @throws IntrusionException
	 */
	byte[] getValidPrintable(String context, byte[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
     * Returns true if input contains only valid printable ASCII characters (32-126).
     * 
     * @param context 
     * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input 
     * 		data to be checked for validity
     * @param maxLength 
     * 		Maximum number of bytes stored in 'input' after canonicalization
     * @param allowNull 
     * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
     * 
     * @return true, if 'input' is less than maxLength after canonicalization and contains only valid, printable characters 
     * 
     * @throws IntrusionException
     */
	boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 *  @param context 
	 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 *  @param input 
	 *  		data to be returned as valid and printable
	 *  @param maxLength 
	 *  		Maximum number of bytes stored in 'input' after canonicalization
	 *  @param allowNull 
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *  
	 *  @return a String containing only printable characters, made up of data from 'input'
	 *  
	 *  @throws ValidationException
	 */
	String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException;

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate 
	 * a descriptive ValidationException, and input that is clearly an attack will generate a 
	 * descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		data to be returned as valid and printable
	 * @param maxLength 
	 * 		Maximum number of bytes stored in 'input' after canonicalization
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return a String containing only printable characters, made up of data from 'input'
	 * 
	 * @throws IntrusionException
	 */
	String getValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if input is a valid redirect location, as defined by "ESAPI.properties".
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		redirect location to be checked for validity, according to rules set in "ESAPI.properties"
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * 
	 * @return true, if 'input' is a valid redirect location, as defined by "ESAPI.properties", false otherwise.
	 * 
	 * @throws IntrusionException
	 */
	boolean isValidRedirectLocation(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 * 
	 *  @param context 
	 *  		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 *  @param input 
	 *  		redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
	 *  @param allowNull 
	 *  		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 *  
	 *  @return A canonicalized and validated redirect location, as defined in "ESAPI.properties"
	 *  
	 *  @throws ValidationException
	 *  @throws IntrusionException
	 */
	String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 * 
	 * @param context 
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input 
	 * 		redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
	 * @param allowNull 
	 * 		If allowNull is true then an input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList 
	 * 		If validation is in error, resulting error will be stored in the errorList by context
	 * 
	 * @return A canonicalized and validated redirect location, as defined in "ESAPI.properties"
	 * 
	 * @throws IntrusionException
	 */
	String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Reads from an input stream until end-of-line or a maximum number of
	 * characters. This method protects against the inherent denial of service
	 * attack in reading until the end of a line. If an attacker doesn't ever
	 * send a newline character, then a normal input stream reader will read
	 * until all memory is exhausted and the platform throws an OutOfMemoryError
	 * and probably terminates.
	 * 
	 * @param inputStream 
	 * 		The InputStream from which to read data
	 * @param maxLength 
	 * 		Maximum characters allowed to be read in per line
	 * 
	 * @return a String containing the current line of inputStream
	 * 
	 * @throws ValidationException
	 */
	String safeReadLine(InputStream inputStream, int maxLength) throws ValidationException;

}

