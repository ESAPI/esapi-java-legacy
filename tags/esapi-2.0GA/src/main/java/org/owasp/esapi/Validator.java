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

import java.io.File;
import java.io.InputStream;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

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

	void addRule( ValidationRule rule );

	ValidationRule getRule( String name );

	/**
	 * Calls isValidInput and returns true if no exceptions are thrown.
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Calls isValidInput and returns true if no exceptions are thrown.
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls isValidInput and returns true if no exceptions are thrown.
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws IntrusionException;

	/**
	 * Calls isValidInput and returns true if no exceptions are thrown.
	 */
	boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) throws IntrusionException;

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
	 * Returns validated input as a String with optional canonicalization. Invalid input will generate a descriptive ValidationException,
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
	 * @param canonicalize
	 *      If canonicalize is true then input will be canonicalized before validation
	 *
	 * @return The canonicalized user input.
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidInput with the supplied errorList to capture ValidationExceptions
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidInput with the supplied errorList to capture ValidationExceptions
	 */
	String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls isValidDate and returns true if no exceptions are thrown.
	 */
	boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException;

	/**
	 * Calls isValidDate and returns true if no exceptions are thrown.
	 */
	boolean isValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidDate with the supplied errorList to capture ValidationExceptions
	 */
	Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidSafeHTML and returns true if no exceptions are thrown.
	 */
	boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidSafeHTML and returns true if no exceptions are thrown.
	 */
	boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns canonicalized and validated "safe" HTML that does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else.
	 * Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way, as this is an extremely difficult problem.
	 *
	 * @param context
	 * 		A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
	 * @param input
	 * 		The actual user input data to validate.
	 * @param maxLength
	 * 		The maximum String length allowed.
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
	 * Calls getValidSafeHTML with the supplied errorList to capture ValidationExceptions
	 */
	String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidCreditCard and returns true if no exceptions are thrown.
	 */
	boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidCreditCard and returns true if no exceptions are thrown.
	 */
	boolean isValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidCreditCard with the supplied errorList to capture ValidationExceptions
	 */
	String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
	 */
	boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidDirectoryPath and returns true if no exceptions are thrown.
	 */
	boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Returns a canonicalized and validated directory path as a String, provided that the input
	 * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent. Invalid input
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
	 *
	 * @return A valid directory path
	 *
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	String getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidDirectoryPath with the supplied errorList to capture ValidationExceptions
	 */
	String getValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidFileName with the default list of allowedExtensions
	 */
	boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidFileName with the default list of allowedExtensions
	 */
	boolean isValidFileName(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidFileName and returns true if no exceptions are thrown.
	 */
	boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidFileName and returns true if no exceptions are thrown.
	 */
	boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidFileName with the supplied errorList to capture ValidationExceptions
	 */
	String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidNumber and returns true if no exceptions are thrown.
	 */
	boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidNumber and returns true if no exceptions are thrown.
	 */
	boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidSafeHTML with the supplied errorList to capture ValidationExceptions
	 */
	Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidInteger and returns true if no exceptions are thrown.
	 */
	boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidInteger and returns true if no exceptions are thrown.
	 */
	boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidInteger with the supplied errorList to capture ValidationExceptions
	 */
	Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidDouble and returns true if no exceptions are thrown.
	 */
	boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidDouble and returns true if no exceptions are thrown.
	 */
	boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidDouble with the supplied errorList to capture ValidationExceptions
	 */
	Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidFileContent and returns true if no exceptions are thrown.
	 */
	boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidFileContent and returns true if no exceptions are thrown.
	 */
	boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidFileContent with the supplied errorList to capture ValidationExceptions
	 */
	byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidFileUpload and returns true if no exceptions are thrown.
	 */
	boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException;

	/**
	 * Calls getValidFileUpload and returns true if no exceptions are thrown.
	 */
	boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidFileUpload with the supplied errorList to capture ValidationExceptions
	 */
	void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidListItem and returns true if no exceptions are thrown.
	 */
	boolean isValidListItem(String context, String input, List<String> list) throws IntrusionException;

	/**
	 * Calls getValidListItem and returns true if no exceptions are thrown.
	 */
	boolean isValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) throws IntrusionException;

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
	String getValidListItem(String context, String input, List<String> list) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidListItem with the supplied errorList to capture ValidationExceptions
	 */
	String getValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls assertValidHTTPRequestParameterSet and returns true if no exceptions are thrown.
	 */
	boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws IntrusionException;

	/**
	 * Calls assertValidHTTPRequestParameterSet and returns true if no exceptions are thrown.
	 */
	boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

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
	void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException, IntrusionException;

	/**
	 * Calls getValidHTTPRequestParameterSet with the supplied errorList to capture ValidationExceptions
	 */
	void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidPrintable and returns true if no exceptions are thrown.
	 */
	boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws IntrusionException;

        /**
	 * Calls getValidPrintable and returns true if no exceptions are thrown.
	 */
	boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws ValidationException;

	/**
	 * Calls getValidPrintable with the supplied errorList to capture ValidationExceptions
	 */
	char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;


	/**
	 * Calls getValidPrintable and returns true if no exceptions are thrown.
	 */
	boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

        /**
	 * Calls getValidPrintable and returns true if no exceptions are thrown.
	 */
	boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

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
	 * Calls getValidPrintable with the supplied errorList to capture ValidationExceptions
	 */
	String getValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

	/**
	 * Calls getValidRedirectLocation and returns true if no exceptions are thrown.
	 */
	boolean isValidRedirectLocation(String context, String input, boolean allowNull);

        /**
	 * Calls getValidRedirectLocation and returns true if no exceptions are thrown.
	 */
	boolean isValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errorList);

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
	 * Calls getValidRedirectLocation with the supplied errorList to capture ValidationExceptions
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

