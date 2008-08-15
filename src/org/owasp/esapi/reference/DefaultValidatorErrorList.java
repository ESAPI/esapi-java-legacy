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
package org.owasp.esapi.reference;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import org.owasp.esapi.errors.ValidationException;

/**
 * The ValidatorErrorList interface defines a collection of ValidationExceptions
 * so that groups of validation functions can be called in a non-blocking fashion.
 * <P>
 * <img src="doc-files/Validator.jpg" height="600">
 * <P>
 * 
 * @author Jim Manico (jim.manico .at. aspectsecurity.com) 
 * 		   <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since August 15, 2008
 */
public class DefaultValidatorErrorList implements org.owasp.esapi.ValidatorErrorList {

	/**
	 * Error list of ValidationException's
	 */
	private Hashtable errorList = new Hashtable();

	/**
	 * Adds a new error to list with a unique named context.
	 * No action taken if either element is null. 
	 * Existing contexts will be overwritten.
	 * 
	 * @param context unique named context for this ValidationErrorList
	 * @param ve
	 */
	public void addError(String context, ValidationException ve) {
		if ((context != null) && (ve != null)) {
			errorList.put(context, ve);
		}
	}

	/**
	 * Returns list of ValidationException, or empty list of no errors exist.
	 * 
	 * @return List
	 */
	public List errors() {
		ArrayList validationExceptionList = new ArrayList(errorList.size());
		for (Enumeration e = errorList.elements() ; e.hasMoreElements() ;) {
			validationExceptionList.add((ValidationException)e.nextElement());
	     }

		return validationExceptionList;
	}

	/**
	 * Retrieves error for given context if one exists.
	 * 
	 * @param context unique name for each error
	 * @return ValidationException or null for given context
	 */
	public ValidationException getError(String context) {
		if (errorList == null || context == null) return null;
		
		Object returnValue = errorList.get(context);
		if (returnValue == null) return null;
		
		return (ValidationException)returnValue;
	}

	/**
	 * Returns true if this list of empty.
	 * 
	 * @return boolean
	 */
	public boolean isEmpty() {
		if ((errorList == null) || (errorList.size() == 0)) return true;
		return false;
	}
}
