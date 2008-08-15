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

import java.util.List;

import org.owasp.esapi.ValidatorErrorList;
import org.owasp.esapi.errors.ValidationException;


/**
 * The ValidatorErrorList interface defines a collection of errors
 * so that groups of validation functions can be called in
 * a non-blocking fashion.
 * <P>
 * <img src="doc-files/Validator.jpg" height="600">
 * <P>
 * 
 * @author Jim Manico (jim.manico .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since August 15, 2008
 */
public interface ValidatorErrorList {

	/**
	 * Return new empty ValidatorErrorList.
	 * 
	 * @return ValidatorErrorList
	 */
    public ValidatorErrorList createValidatorErrorList();

	/**
	 * Returns true if this list of empty.
	 * 
	 * @return boolean
	 */
    public boolean isEmpty();

	/**
	 * Returns list of ValidationException, or empty list of no errors exist.
	 * 
	 * @return List
	 */
    public List errors();
    
	/**
	 * Retrieves error for given context if one exists.
	 * 
	 * @param context unique name for each error
	 * @return ValidationException or null for given context
	 */
    public ValidationException getError(String context);

	/**
	 * Adds a new error to list with a unique named context.
	 * 
	 * @param context unique named context for this ValidationErrorList
	 * @param ve
	 */
    public void addError(String context, ValidationException ve);
}

