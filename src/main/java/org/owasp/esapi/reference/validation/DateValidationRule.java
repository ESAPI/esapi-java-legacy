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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.ValidationErrorList;
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
	
	public DateValidationRule( String typeName, Encoder encoder, DateFormat newFormat ) {
		super( typeName, encoder );      
		setDateFormat( newFormat );
	}
	
    public final void setDateFormat( DateFormat newFormat ) {
        if (newFormat == null) {
			throw new IllegalArgumentException("DateValidationRule.setDateFormat requires a non-null DateFormat");
		}
    	// CHECKME fail fast?
/*		
  		try {
			newFormat.parse(new Date());
		} catch (ParseException e) {
			throw new IllegalArgumentException(e);
		}
*/
        this.format = newFormat;
        this.format.setLenient( ESAPI.securityConfiguration().getLenientDatesAccepted() );
    }

    /**
     * {@inheritDoc}
     */
	public Date getValid( String context, String input ) throws ValidationException {
		return safelyParse(context, input, false);
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public Date sanitize( String context, String input )  {
		return sanitize(context, input, null);
	}
	
	/**
     * Same as sanitize(String, String) except it returns any ValidationException generated in the provided errorList.
     * 
     *   @param errorList The error list to add any ValidationException to.
     *   @return The valid sanitized Date, or Date(0) if the supplied input was not a valid date.
     */
    public Date sanitize( String context, String input, ValidationErrorList errorList )  {
        Date date = new Date(0);
        try {
            date = safelyParse(context, input, true);
        } catch (ValidationException e) {
            if (errorList != null) {
                errorList.addError(context, e);
            }
        }
        return date;
    }
	    
	private Date safelyParse(String context, String input, boolean sanitize)
			throws ValidationException {
		// CHECKME should this allow empty Strings? "   " use IsBlank instead?
		if (StringUtilities.isEmpty(input)) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException(context + ": Input date required",
					"Input date required: context=" + context + ", input="
							+ input, context);
		}

		 String canonical = encoder.canonicalize(input);
	        try {
	            Date rval = format.parse(canonical);
	            if (sanitize) {
	                String cycled = format.format(rval);
	                if (!cycled.equals(canonical)) {
	                    throw new Exception("Parameter date is not a clean translation between String and Date contexts.  Check input for additional characters");
	                }
	            }
	            return rval;
		} catch (Exception e) {
			throw new ValidationException(context
					+ ": Invalid date must follow the "
					+ format.getNumberFormat() + " format",
					"Invalid date: context=" + context + ", format=" + format
							+ ", input=" + input, e, context);
		}
	}
}
