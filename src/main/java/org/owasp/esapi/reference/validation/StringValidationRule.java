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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import org.owasp.esapi.Encoder;
import org.owasp.esapi.errors.EncodingException;
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
public class StringValidationRule extends BaseValidationRule {

	protected List whitelistPatterns = new ArrayList();
	protected List blacklistPatterns = new ArrayList();
	protected int minLength = 0;
	protected int maxLength = Integer.MAX_VALUE;

	public StringValidationRule( String typeName ) {
		super( typeName );
	}
	
	public StringValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public StringValidationRule( String typeName, Encoder encoder, String whitelistPattern ) {
		super( typeName, encoder );
		addWhitelistPattern( whitelistPattern );
	}
	
	public void addWhitelistPattern( String pattern ) {
		try {
			Pattern p = Pattern.compile( pattern );
			whitelistPatterns.add( p );
		} catch( Exception e ) {
			throw new RuntimeException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}

	public void addBlacklistPattern( String pattern ) {
		try {
			Pattern p = Pattern.compile( pattern );
			blacklistPatterns.add( p );
		} catch( Exception e ) {
			throw new RuntimeException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}
	
	public void setMinimumLength( int length ) {
		minLength = length;
	}
	public void setMaximumLength( int length ) {
		maxLength = length;
	}

	public Object getValid( String context, String input ) throws ValidationException {
    	
	    // check null
	    if ( input == null || input.length()==0 ) {
			if (allowNull) return null;
   			throw new ValidationException( context + ": Input required.", "Input required: context=" + context + "), input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = null;
	    try {
	    	canonical = encoder.canonicalize( input );
	    } catch (EncodingException e) {
	        throw new ValidationException( context + ": Invalid input. Encoding problem detected.", "Error canonicalizing user input", e, context);
	    }

		// check length
		if (canonical.length() < minLength) {
			throw new ValidationException( context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (canonical.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + "), input=" + input, context );
		}

		if (canonical.length() > maxLength) {
			throw new ValidationException( context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (canonical.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + ", input=" + input, context );
		}
		
		// check whitelist patterns
		Iterator iWhite = whitelistPatterns.iterator();
		while( iWhite.hasNext() ) {
			Pattern p = (Pattern)iWhite.next();
			if ( !p.matcher(canonical).matches() ) {
    			throw new ValidationException( context + ": Invalid input. Please conform to regex " + p.pattern() + ( maxLength == Integer.MAX_VALUE ? "" : " with a maximum length of " + maxLength ), "Invalid input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input, context );
			}
		}
		
		// check blacklist patterns
		Iterator iBlack = blacklistPatterns.iterator();
		while( iBlack.hasNext() ) {
			Pattern p = (Pattern)iBlack.next();
			if ( p.matcher(canonical).matches() ) {
    			throw new ValidationException( context + ": Invalid input. Dangerous input matching " + p.pattern() + " detected.", "Dangerous input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input, context );
			}
		}
		
		// validation passed
		return canonical;
	}

	public Object sanitize( String context, String input ) {
		return whitelist( input, DefaultEncoder.CHAR_ALPHANUMERICS );
	}
	
}

