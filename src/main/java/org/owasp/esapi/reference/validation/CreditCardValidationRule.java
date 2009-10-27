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

import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.errors.ValidationException;

/**
 * A validator performs syntax and possibly semantic validation of Credit Card
 * String from an untrusted source.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class CreditCardValidationRule extends BaseValidationRule {
	private int maxCardLength = 19;
	
	/**
	 * Key used to pull out encoder in configuration.  Prefixed with "Validator."
	 */
	protected static final String CREDIT_CARD_VALIDATOR_KEY = "CreditCard";
	
	private StringValidationRule ccrule = null; 
	
	/**
	 * Creates a CreditCardValidator using the rule found in security configuration
	 * @param typeName a description of the type of card being validated
	 * @param encoder
	 */
	public CreditCardValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
		ccrule = readDefaultCreditCardRule();
	}
	
	public CreditCardValidationRule( String typeName, Encoder encoder, StringValidationRule validationRule ) {
		super( typeName, encoder );
		ccrule = validationRule;
	}

	private StringValidationRule readDefaultCreditCardRule() {
		Pattern p = ESAPI.securityConfiguration().getValidationPattern( CREDIT_CARD_VALIDATOR_KEY );
		StringValidationRule ccr = new StringValidationRule( "ccrule", encoder, p.pattern() );
		ccr.setMaximumLength(getMaxCardLength());
		ccr.setAllowNull( false );
		return ccr;
	}
	
    /**
     * {@inheritDoc}
     */
	public String getValid( String context, String input ) throws ValidationException {
		// CHECKME should this allow empty Strings? "   " us IsBlank instead?
	    if ( StringUtils.isEmpty(input) ) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException( context + ": Input credit card required", "Input credit card required: context=" + context + ", input=" + input, context );
	    }
	    
	    String canonical = ccrule.getValid( context, input );

		if( ! validCreditCardFormat(canonical)) {
			throw new ValidationException( context + ": Invalid credit card input", "Invalid credit card input: context=" + context, context );
		}
		
		return canonical;	    
	}

	/**
	 * Performs additional validation on the card nummber.
	 * This implementation performs Luhn algorithm checking
	 * @param ccNum number to be validated
	 * @return true if the ccNum passes the Luhn Algorithm
	 */
	protected boolean validCreditCardFormat(String ccNum) {
		
	    StringBuilder digitsOnly = new StringBuilder();
		char c;
		for (int i = 0; i < ccNum.length(); i++) {
			c = ccNum.charAt(i);
			if (Character.isDigit(c)) {
				digitsOnly.append(c);
			}
		}
	
		int sum = 0;
		int digit = 0;
		int addend = 0;
		boolean timesTwo = false;
	
		for (int i = digitsOnly.length() - 1; i >= 0; i--) {
			// guaranteed to be an int
			digit = Integer.valueOf(digitsOnly.substring(i, i + 1));
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

		return sum % 10 == 0; 
	
	}
	
    /**
     * {@inheritDoc}
     */
	@Override
	public String sanitize( String context, String input ) {
		return whitelist( input, EncoderConstants.CHAR_DIGITS );
	}

	/**
	 * @param ccrule the ccrule to set
	 */
	public void setStringValidatorRule(StringValidationRule ccrule) {
		this.ccrule = ccrule;
	}

	/**
	 * @return the ccrule
	 */
	public StringValidationRule getStringValidatorRule() {
		return ccrule;
	}

	/**
	 * @param maxCardLength the maxCardLength to set
	 */
	public void setMaxCardLength(int maxCardLength) {
		this.maxCardLength = maxCardLength;
	}

	/**
	 * @return the maxCardLength
	 */
	public int getMaxCardLength() {
		return maxCardLength;
	}
}
