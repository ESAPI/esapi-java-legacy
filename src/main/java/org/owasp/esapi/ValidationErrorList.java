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
 * 
 * @created 2007
 */
package org.owasp.esapi;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.owasp.esapi.errors.ValidationException;

/**
 * The ValidationErrorList class defines a well-formed collection of 
 * ValidationExceptions so that groups of validation functions can be 
 * called in a non-blocking fashion.
 * <P>
 * To use the ValidationErrorList to execute groups of validation 
 * attempts, your controller code would look something like:
 * 
 * <PRE>
 * ValidationErrorList() errorList = new ValidationErrorList();.
 * String name  = getValidInput("Name", form.getName(), "SomeESAPIRegExName1", 255, false, errorList);
 * String address = getValidInput("Address", form.getAddress(), "SomeESAPIRegExName2", 255, false, errorList);
 * Integer weight = getValidInteger("Weight", form.getWeight(), 1, 1000000000, false, errorList);
 * Integer sortOrder = getValidInteger("Sort Order", form.getSortOrder(), -100000, +100000, false, errorList);
 * request.setAttribute( "ERROR_LIST", errorList );
 * </PRE>
 * 
 * The at your view layer you would be able to retrieve all
 * of your error messages via a helper function like:
 * 
 * <PRE>
 * public static ValidationErrorList getErrors() {          
 *     HttpServletRequest request = ESAPI.httpUtilities().getCurrentRequest();
 *     ValidationErrorList errors = new ValidationErrorList();
 *     if (request.getAttribute(Constants.ERROR_LIST) != null) {
 *        errors = (ValidationErrorList)request.getAttribute("ERROR_LIST");
 *     }
 * 	   return errors;
 * }
 * </PRE>
 * 
 * You can list all errors like:
 * 
 * <PRE>
 * <%
 *      for (Object vo : errorList.errors()) {
 *         ValidationException ve = (ValidationException)vo;
 * %>
 * <%= ESAPI.encoder().encodeForHTML(ve.getMessage()) %><br/>
 * <%
 *     }
 * %>
 * </PRE>
 * 
 * And even check if a specific UI component is in error via calls like:
 * 
 * <PRE>
 * ValidationException e = errorList.getError("Name");
 * </PRE>
 * 
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @since August 15, 2008
 */
public class ValidationErrorList {

	/**
	 * Error list of ValidationException's
	 */
	private HashMap<String, ValidationException> errorList = new HashMap<String, ValidationException>();

	/**
	 * Adds a new error to list with a unique named context.
	 * No action taken if either element is null. 
	 * Existing contexts will be overwritten.
	 * 
	 * @param context Unique named context for this {@code ValidationErrorList}.
	 * @param vex	A {@code ValidationException}.
	 */
	public void addError(String context, ValidationException vex) {
		if ( context == null ) throw new RuntimeException( "Context cannot be null: " + vex.getLogMessage(), vex );
		if ( vex == null ) throw new RuntimeException( "ValidationException cannot be null for context  (" + context + ")" );
		if (getError(context) != null) throw new RuntimeException("Context (" + context + ") already exists, must be unique");
		errorList.put(context, vex);
	}

	/**
	 * Returns list of ValidationException, or empty list of no errors exist.
	 * 
	 * @return List
	 */
	public List<ValidationException> errors() {
		return new ArrayList<ValidationException>( errorList.values() );
	}

	/**
	 * Retrieves ValidationException for given context if one exists.
	 * 
	 * @param context unique name for each error
	 * @return ValidationException or null for given context
	 */
	public ValidationException getError(String context) {
		if (context == null) return null;		
		return errorList.get(context);
	}

	/**
	 * Returns true if no error are present.
	 * 
	 * @return boolean
	 */
	public boolean isEmpty() {
		return errorList.isEmpty();
	}
	
	/**
	 * Returns the numbers of errors present.
	 * 
	 * @return boolean
	 */
	public int size() {
		return errorList.size();
	}
}
