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
package org.owasp.esapi.interfaces;

import java.io.InputStream;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.ValidationException;

/**
 * The IValidator interface defines a set of methods for canonicalizing and
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
public interface IValidator {

	/**
	 * 
	 * @param context
	 * @param type
	 * @param value
	 * @return
	 * @throws ValidationException
	 */
	public String getValidDataFromBrowser(String context, String type, String value) throws ValidationException;
	
	/**
	 * Gets a valid date from the input.
	 */
	Date getValidDate(String context, String value, DateFormat format) throws ValidationException;	
	
	/**
	 * Returns valid safe HTML from any input string.
	 */
	String getValidSafeHTML(String context, String value) throws ValidationException;

	/**
	 * Checks if input is a valid credit card.
	 */
	boolean isValidCreditCard(String context, String value);

	/**
	 * Checks if input from browser is valid according to the specified type. The types are configured
	 * as regular expressions in ESAPI.config.
	 */
	public boolean isValidDataFromBrowser(String name, String type, String value);

	/**
	 * Checks if input is a valid directory path.
	 */
	boolean isValidDirectoryPath(String context, String value);

	/**
	 * Checks if input is a valid file upload.
	 * 
	 * @param content
	 *            the content
	 * 
	 * @return true, if is valid file upload
	 */
	boolean isValidFileContent(String context, byte[] content);

	/**
	 * Checks if input is a valid file name.
	 * 
	 * @param input
	 *            the input
	 * 
	 * @return true, if is valid file name
	 */
	boolean isValidFileName(String context, String input);

    /**
	 * Checks whether a file upload has a valid name, path, and content.
	 * 
	 * @param filepath
	 *            the filepath
	 * @param filename
	 *            the filename
	 * @param content
	 *            the content
	 * 
	 * @return true if the file is safe
	 */
	boolean isValidFileUpload(String context, String filepath, String filename, byte[] content);

	/**
     * Validate an HTTP requests by comparing parameters, headers, and cookies to a predefined whitelist of allowed
     * characters. See the SecurityConfiguration class for the methods to retrieve the whitelists.
     * 
     * @param request
     * @return
     */
    boolean isValidHTTPRequest(HttpServletRequest request);

	/**
	 * Checks if input is a valid list item.
	 */
	boolean isValidListItem(List list, String value);

	/**
	 * Checks if input is a valid number.
	 */
	boolean isValidNumber(String input);

	/**
	 * Checks if the supplied set of parameters matches the required parameter set, with no extra and no missing parameters.
	 */
	boolean isValidParameterSet(Set required, Set optional);

	/**
	 * Checks if input is valid printable ASCII characters.
	 */
    boolean isValidPrintable(byte[] input);

	/**
     * Checks if input is valid printable ASCII characters.
     */
    boolean isValidPrintable(String input);

	/**
	 * Checks if input is a valid redirect location.
	 */
	boolean isValidRedirectLocation(String context, String location);

	/**
	 * Checks if input is valid safe HTML. Implementors should reference the OWASP AntiSamy project for ideas
	 * on how to do HTML validation in a whitelist way.
	 */
	boolean isValidSafeHTML(String context, String input);

   
	/**
	 * Reads from an input stream until end-of-line or a maximum number of
	 * characters. This method protects against the inherent denial of service
	 * attack in reading until the end of a line. If an attacker doesn't ever
	 * send a newline character, then a normal input stream reader will read
	 * until all memory is exhausted and the platform throws an OutOfMemoryError
	 * and probably terminates.
	 * 
	 * @param inputStream
	 *            the InputStream
	 * @param maxsChar
	 *            the maxs char
	 * 
	 * @return the line
	 * 
	 * @throws ValidationException
	 *             the validation exception
	 */
	// FIXME: ENHANCE timeout too!
	String safeReadLine(InputStream inputStream, int maxsChar) throws ValidationException;

}
