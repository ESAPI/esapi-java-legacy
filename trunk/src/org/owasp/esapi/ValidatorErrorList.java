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
import org.owasp.esapi.errors.ValidationException;

/**
 * The ValidatorErrorList interface defines a set of methods for storing
 * and displaying a list of validation errors.
 * <P>
 * <img src="doc-files/Validator.jpg" height="600">
 * <P>
 * 
 * @author Jim Manico (jim.manico .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since August 14, 2008
 */
public interface ValidatorErrorList {

	//build an empty ValidationErrorList
	public ValidatorErrorList createValidatorErrorList();

	//verify if errorList is empty
	public boolean isEmpty();

	//returns list of ValidationException or an empty list (never null)
	public List errors();
	
	//returns null if error does not exist for given context
	public ValidationException getError(String context);

	//adds new error to list with a unique named context
	//does nothing if either element is null
	public void addError(String context, ValidationException ve);
}
