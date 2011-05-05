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


import java.util.HashSet;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
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

	private String typeName = null;
	protected boolean allowNull = false;
	protected Encoder encoder = null;
	
	private BaseValidationRule() {
		// prevent use of no-arg constructor
	}
	
	public BaseValidationRule( String typeName ) {
		this();
		setEncoder( ESAPI.encoder() );
		setTypeName( typeName );
	}
	
	public BaseValidationRule( String typeName, Encoder encoder ) {
		this();
		setEncoder( encoder );
		setTypeName( typeName );
	}
	
    /**
     * {@inheritDoc}
	 */
	public void setAllowNull( boolean flag ) {
		allowNull = flag;
	}

    /**
     * {@inheritDoc}
	 */
	public String getTypeName() {
		return typeName;
	}
	
    /**
     * {@inheritDoc}
	 */
	public final void setTypeName( String typeName ) {
		this.typeName = typeName;
	}
	
    /**
     * {@inheritDoc}
	 */
	public final void setEncoder( Encoder encoder ) {
		this.encoder = encoder;
	}
	
    /**
     * {@inheritDoc}
	 */
	public void assertValid( String context, String input ) throws ValidationException {
		getValid( context, input, null );
	}

    /**
     * {@inheritDoc}
	 */
	public Object getValid( String context, String input, ValidationErrorList errorList ) throws ValidationException {
		Object valid = null;
		try {
			valid = getValid( context, input );
		} catch (ValidationException e) {
			errorList.addError(context, e);
		}
		return valid;
	}
	
    /**
     * {@inheritDoc}
	 */
	public Object getSafe( String context, String input ) {
		Object valid = null;
		try {
			valid = getValid( context, input );
		} catch ( ValidationException e ) {
			return sanitize( context, input );
		}
		return valid;
	}

	/**
	 * The method is similar to ValidationRuile.getSafe except that it returns a
	 * harmless object that <b>may or may not have any similarity to the original
	 * input (in some cases you may not care)</b>. In most cases this should be the
	 * same as the getSafe method only instead of throwing an exception, return
	 * some default value.
	 * 
	 * @param context
	 * @param input
	 * @return a parsed version of the input or a default value.
	 */
	protected abstract Object sanitize( String context, String input );
	
    /**
     * {@inheritDoc}
	 */
	public boolean isValid( String context, String input ) {
		boolean valid = false;
		try {
			getValid( context, input );
			valid = true;
		} catch( Exception e ) {
			valid = false;
		}
		
		return valid;
	}

    /**
     * {@inheritDoc}
	 */
	public String whitelist( String input, char[] whitelist) {
		return whitelist(input, charArrayToSet(whitelist));
	}
	
	/**
	 * Removes characters that aren't in the whitelist from the input String.  
	 * O(input.length) whitelist performance
	 * @param input String to be sanitized
	 * @param whitelist allowed characters
	 * @return input stripped of all chars that aren't in the whitelist 
	 */
	public String whitelist( String input, Set<Character> whitelist) {
		StringBuilder stripped = new StringBuilder();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);
			if (whitelist.contains(c)) {
				stripped.append(c);
			}
		}
		return stripped.toString();
	}
	
	// CHECKME should be moved to some utility class (Would potentially be used by new EncoderConstants class)
	// Is there a standard way to convert an array of primitives to a Collection
	/**
	 * Convert an array of characters to a {@code Set<Character>} (so duplicates
	 * are removed).
	 * @param array The character array.
	 * @return A {@code Set<Character>} of the unique characters from {@code array}
	 *         is returned.
	 */
	public static Set<Character> charArrayToSet(char[] array) {
		Set<Character> toReturn = new HashSet<Character>(array.length);
		for (char c : array) {
			toReturn.add(c);
		}
		return toReturn;
	}
	
	public boolean isAllowNull() {
		return allowNull;
	}

	public Encoder getEncoder() {
		return encoder;
	}
}
