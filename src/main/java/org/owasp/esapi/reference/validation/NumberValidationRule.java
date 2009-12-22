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

import org.owasp.esapi.Encoder;
import org.owasp.esapi.StringUtilities;
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
public class NumberValidationRule extends BaseValidationRule {
	
	private double minValue = Double.NEGATIVE_INFINITY;
	private double maxValue = Double.POSITIVE_INFINITY;
	
	public NumberValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public NumberValidationRule( String typeName, Encoder encoder, double minValue, double maxValue ) {
		super( typeName, encoder );
		this.minValue = minValue;
		this.maxValue = maxValue;

		// CHECKME fail fast?		
//		if (minValue > maxValue) {
//			throw new IllegalArgumentException("Invalid number input: context Validation parameter error for number: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ")");
//		}
	}

    /**
     * {@inheritDoc}
     */
	public Double getValid( String context, String input ) throws ValidationException {
		return safelyParse(context, input);
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public Double sanitize( String context, String input ) {
		Double toReturn = Double.valueOf(0);
		try {
			toReturn = safelyParse(context, input);
		} catch (ValidationException e) {
			// do nothing
		}
		return toReturn;
	}

	private Double safelyParse(String context, String input)
			throws ValidationException {
		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtilities.isEmpty(input) ) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException( context + ": Input number required", "Input number required: context=" + context + ", input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = encoder.canonicalize( input );

		if (minValue > maxValue) {
			throw new ValidationException( context + ": Invalid number input: context", "Validation parameter error for number: maxValue ( " + maxValue + ") must be greater than minValue ( " + minValue + ") for " + context, context );
		}
		
		Double d;
		// validate min and max
		try {
			d = Double.valueOf(Double.parseDouble( canonical ));
		} catch (NumberFormatException e) {
			throw new ValidationException( context + ": Invalid number input", "Invalid number input format: context=" + context + ", input=" + input, e, context);
		}
	
		if (d.isInfinite()) {
			throw new ValidationException( "Invalid number input: context=" + context, "Invalid double input is infinite: context=" + context + ", input=" + input, context );
	}
		if (d.isNaN()) {
			throw new ValidationException( "Invalid number input: context=" + context, "Invalid double input is not a number: context=" + context + ", input=" + input, context );
		}
		if (d.doubleValue() < minValue) {
			throw new ValidationException( "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
		}
		if (d.doubleValue() > maxValue) {
			throw new ValidationException( "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context, "Invalid number input must be between " + minValue + " and " + maxValue + ": context=" + context + ", input=" + input, context );
		}			
		return d;
	}
}
