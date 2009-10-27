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

import org.apache.commons.lang.StringUtils;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.ValidationException;


/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class IntegerValidationRule extends BaseValidationRule {
	
	private int minValue = Integer.MIN_VALUE;
	private int maxValue = Integer.MAX_VALUE;
	
	public IntegerValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public IntegerValidationRule( String typeName, Encoder encoder, int minValue, int maxValue ) {
		super( typeName, encoder );
		this.minValue = minValue;
		this.maxValue = maxValue;
		
		// CHECKME fail fast?
//		if (minValue > maxValue) {
//			throw new IllegalArgumentException("minValue cannot be greater than maxValue");
//		}
	}

	public Integer getValid( String context, String input ) throws ValidationException {
		return safelyParse(context, input);
	}

	private Integer safelyParse(String context, String input)
			throws ValidationException {
		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtils.isEmpty(input) ) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException( context + ": Input number required", "Input number required: context=" + context + ", input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = null;
	    try {
	    	canonical = encoder.canonicalize( input );
	    } catch (EncodingException e) {
	        throw new ValidationException( context + ": Invalid number input. Encoding problem detected.", "Error canonicalizing user input", e, context);
	    }

		if (minValue > maxValue) {
			throw new ValidationException( context + ": Invalid number input: context", "Validation parameter error for number: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ") for " + context, context );
		}
		
		// validate min and max
		try {
			int i = Integer.valueOf(canonical);
			if (i < minValue) {
				throw new ValidationException( "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
			}
			if (i > maxValue) {
				throw new ValidationException( "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
			}			
			return i;
		} catch (NumberFormatException e) {
			throw new ValidationException( context + ": Invalid number input", "Invalid number input format: context=" + context + ", input=" + input, e, context);
		}
	}

	@Override
	public Integer sanitize( String context, String input ) {
		Integer toReturn = Integer.valueOf( 0 );
		try {
			toReturn = safelyParse(context, input);
		} catch (ValidationException e ) {
			// do nothing
	}
		return toReturn;
	}
	
}
