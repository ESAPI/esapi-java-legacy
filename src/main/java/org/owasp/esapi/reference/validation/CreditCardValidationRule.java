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
import java.util.regex.Pattern;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultEncoder;


/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class CreditCardValidationRule extends BaseValidationRule {

	private StringValidationRule ccrule = null; 
	
	public CreditCardValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
		ccrule = getCCRule( encoder );
	}

	public CreditCardValidationRule( String typeName, Encoder encoder, DateFormat format ) {
		super( typeName, encoder );
		ccrule = getCCRule( encoder );
	}

	private StringValidationRule getCCRule( Encoder encoder ) {
		Pattern p = ESAPI.securityConfiguration().getValidationPattern( "CreditCard" );
		StringValidationRule ccr = new StringValidationRule( "ccrule", encoder, p.pattern() );
		ccr.setMaximumLength(19);
		ccr.setAllowNull( false );
		return ccr;
	}
	
	public Object getValid( String context, String input ) throws ValidationException {

		// check null
	    if ( input == null || input.length()==0 ) {
			if (allowNull) return null;
			throw new ValidationException( context + ": Input credit card required", "Input credit card required: context=" + context + ", input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = (String)ccrule.getValid( context, input );

		// perform Luhn algorithm checking
	    StringBuilder digitsOnly = new StringBuilder();
		char c;
		for (int i = 0; i < canonical.length(); i++) {
			c = canonical.charAt(i);
			if (Character.isDigit(c)) {
				digitsOnly.append(c);
			}
		}
	
		int sum = 0;
		int digit = 0;
		int addend = 0;
		boolean timesTwo = false;
	
		for (int i = digitsOnly.length() - 1; i >= 0; i--) {
			digit = Integer.parseInt(digitsOnly.substring(i, i + 1));
			if (timesTwo) {
				addend = digit * 2;
				if (addend > 9) {
					addend -= 9;
				}
			} else {
				addend = digit;
			}
			sum += addend;
			timesTwo = !timesTwo;
		}
	
		int modulus = sum % 10;
		if (modulus != 0) throw new ValidationException( context + ": Invalid credit card input", "Invalid credit card input: context=" + context, context );
			
		return canonical;	    
	}
	
	public Object sanitize( String context, String input ) {
		return whitelist( input, DefaultEncoder.CHAR_DIGITS );
	}
	
	
}
