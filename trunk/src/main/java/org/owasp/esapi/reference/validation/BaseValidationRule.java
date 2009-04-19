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
package org.owasp.esapi.reference.validation;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;


/**
 * A ValidationRule performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public abstract class BaseValidationRule implements ValidationRule {

	protected String typeName = null;
	protected boolean allowNull = false;
	protected Encoder encoder = null;
	
	private BaseValidationRule() {
		// prevent use of no-arg constructor
	}
	
	public BaseValidationRule( String typeName ) {
		setEncoder( ESAPI.encoder() );
		setTypeName( typeName );
	}
	
	public BaseValidationRule( String typeName, Encoder encoder ) {
		setEncoder( encoder );
		setTypeName( typeName );
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#getValid(java.lang.String, java.lang.String)
	 */
	public abstract Object getValid( String context, String input ) throws ValidationException;

	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#setAllowNull(boolean)
	 */
	public void setAllowNull( boolean flag ) {
		allowNull = flag;
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#getTypeName()
	 */
	public String getTypeName() {
		return typeName;
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#setTypeName(java.lang.String)
	 */
	public void setTypeName( String typeName ) {
		this.typeName = typeName;
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#setEncoder(org.owasp.esapi.Encoder)
	 */
	public void setEncoder( Encoder encoder ) {
		this.encoder = encoder;
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#assertValid(java.lang.String, java.lang.String)
	 */
	public void assertValid( String context, String input ) throws ValidationException {
		getValid( context, input, null );
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#getValid(java.lang.String, java.lang.String, org.owasp.esapi.ValidationErrorList)
	 */
	public Object getValid( String context, String input, ValidationErrorList errorList ) throws ValidationException {
		try {
			return getValid( context, input );
		} catch (ValidationException e) {
			errorList.addError(context, e);
		}
		return null;
	}
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#getSafe(java.lang.String, java.lang.String)
	 */
	public Object getSafe( String context, String input ) {
		try {
			Object o = getValid( context, input );
			return o;
		} catch ( ValidationException e ) {
			return sanitize( context, input );
		}
	}

	protected abstract Object sanitize( String context, String input );
	
	
	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#isValid(java.lang.String, java.lang.String)
	 */
	public boolean isValid( String context, String input ) {
		try {
			getValid( context, input );
			return true;
		} catch( ValidationException e ) {
			return false;
		} catch( Exception e ) {
			return false;
		}
	}

	/* (non-Javadoc)
	 * @see org.owasp.esapi.reference.validation.IValidationRule#whitelist(java.lang.String, char[])
	 */
	public String whitelist( String input, char[] list ) {
		StringBuffer stripped = new StringBuffer();
		char c;
		for (int i = 0; i < input.length(); i++) {
			c = input.charAt(i);
			if (Character.isDigit(c)) {
				stripped.append(c);
			}
		}
		return stripped.toString();
	}
	
	
}

