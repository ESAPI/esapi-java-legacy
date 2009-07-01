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

import java.text.DateFormat;
import java.util.Date;

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
public class DateValidationRule extends BaseValidationRule {
	
	private DateFormat format = DateFormat.getDateInstance();
	
	public DateValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public DateValidationRule( String typeName, Encoder encoder, DateFormat format ) {
		super( typeName, encoder );
		setDateFormat( format );
	}
	
	public void setDateFormat( DateFormat format ) {
		this.format = format;
	}

	public Object getValid( String context, String input ) throws ValidationException {

		// check null
	    if ( input == null || input.length()==0 ) {
			if (allowNull) return null;
			throw new ValidationException( context + ": Input date required", "Input date required: context=" + context + ", input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = null;
	    try {
	    	canonical = encoder.canonicalize( input );
	    } catch (EncodingException e) {
	        throw new ValidationException( context + ": Invalid date input. Encoding problem detected.", "Error canonicalizing user input", e, context);
	    }

		try {			
			Date date = format.parse( canonical );
			// validation passed
			return date;
		} catch (Exception e) {
			throw new ValidationException( context + ": Invalid date must follow the " + format.getNumberFormat() + " format", "Invalid date: context=" + context + ", format=" + format + ", input=" + input, e, context);
		}
	}
	
	public Object sanitize( String context, String input )  {
		return new Date();
	}
	
}
