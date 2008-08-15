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
 * interface to accomodate their own data formats. Rather than throw exceptions,
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
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException. 
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
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns canonicalized and validated input as a String. Invalid input will generate a descriptive ValidationException, 
	 * and input that is clearly an attack will generate a descriptive IntrusionException. 
	 * 
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errorList If validation is in error, resulting error will be stored in the errorList by context
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	/**
	 * Returns true if input is a valid date according to the specified date format.
	 */
	boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException;	
	
	/**
	 * Returns a valid date as a Date. Invalid input will generate a descriptive ValidationException and store it inside of 
	 * the errorList argument, and input that is clearly an attack will generate a descriptive IntrusionException. 
	 */
	Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;	
	
	
	/**
	 * Returns true if input is "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 */
	boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 */
	String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns canonicalized and validated "safe" HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem. Instead of
	 * throwing a ValidationException on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns true if input is a valid credit card. Maxlength is mandated by valid credit card type. 
	 */
	boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated credit card number as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	
	
	/**
	 * Returns true if input is a valid directory path.
	 */
	boolean isValidDirectoryPath(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated directory path as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidDirectoryPath(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated directory path as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidDirectoryPath(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	
	/**
	 * Returns true if input is a valid file name.
	 */
	boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated file name as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidFileName(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a canonicalized and validated file name as a String. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidFileName(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	
	
	/**
	 * Returns true if input is a valid number.
	 */
	boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a validated number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
	 * Returns true if input is a valid integer.
	 */
	boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated integer as an int. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException;
	
	/**
	 * Returns a validated integer as an int. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;
	
	
	/**
	 * Returns true if input is a valid double.
	 */
	boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a validated real number as a double. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	
	/**
	 * Returns true if input is valid file content.
	 */
	boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Returns validated file content as a byte array. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns validated file content as a byte array. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
	 * Returns true if a file upload has a valid name, path, and content.
	 */
	boolean isValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Validates the filepath, filename, and content of a file. Invalid input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	void assertValidFileUpload(String context, String filepath, String filename, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
     * Validate the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
     * characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.
     */
	boolean isValidHTTPRequest() throws IntrusionException;
	
	/**
	 * Validates the current HTTP request by comparing parameters, headers, and cookies to a predefined whitelist of allowed
	 * characters. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	void assertIsValidHTTPRequest() throws ValidationException, IntrusionException;
	
	
	/**
	 * Returns true if input is a valid list item.
	 */
	boolean isValidListItem(String context, String input, List list) throws IntrusionException;

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidListItem(String context, String input, List list) throws ValidationException, IntrusionException;

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidListItem(String context, String input, List list, ValidationErrorList errorList) throws IntrusionException;

	
	
	/**
	 * Returns true if the parameters in the current request contain all required parameters and only optional ones in addition.
	 */
	boolean isValidHTTPRequestParameterSet(String context, Set required, Set optional) throws IntrusionException;

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional) throws ValidationException, IntrusionException;
	
	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 */
	void assertIsValidHTTPRequestParameterSet(String context, Set required, Set optional, ValidationErrorList errorList) throws IntrusionException;
	
	
	
	/**
	 * Returns true if input is valid printable ASCII characters.
	 */
	boolean isValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	byte[] getValidPrintable(String context, byte[] input, int maxLength, boolean allowNull) throws ValidationException;

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 */
	byte[] getValidPrintable(String context, byte[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
     * Returns true if input is valid printable ASCII characters (32-126).
     */
	boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException;

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate 
	 * a descriptive ValidationException, and input that is clearly an attack will generate a 
	 * descriptive IntrusionException. Instead of throwing a ValidationException on error, 
	 * this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	/**
	 * Returns true if input is a valid redirect location.
	 */
	boolean isValidRedirectLocation(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. 
	 */
	String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException. Instead of throwing a ValidationException 
	 * on error, this variant will store the exception inside of the ValidationErrorList.
	 */
	String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	
	
	/**
	 * Reads from an input stream until end-of-line or a maximum number of
	 * characters. This method protects against the inherent denial of service
	 * attack in reading until the end of a line. If an attacker doesn't ever
	 * send a newline character, then a normal input stream reader will read
	 * until all memory is exhausted and the platform throws an OutOfMemoryError
	 * and probably terminates.
	 */
	String safeReadLine(InputStream inputStream, int maxLength) throws ValidationException;

}

