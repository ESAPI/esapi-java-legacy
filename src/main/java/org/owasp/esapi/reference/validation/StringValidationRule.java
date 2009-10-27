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
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.lang.StringUtils;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.EncoderConstants;
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
 * 
 * http://en.wikipedia.org/wiki/Whitelist
 */
public class StringValidationRule extends BaseValidationRule {

	protected List<Pattern> whitelistPatterns = new ArrayList<Pattern>();
	protected List<Pattern> blacklistPatterns = new ArrayList<Pattern>();
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
	
	/**
	 * @throws IllegalArgumentException if pattern is null
	 */
	public void addWhitelistPattern( String pattern ) {
		 if (pattern == null) {
			 throw new IllegalArgumentException("Pattern cannot be null");
		 }
		try {
			whitelistPatterns.add( Pattern.compile( pattern ) );
		} catch( PatternSyntaxException e ) {
			throw new IllegalArgumentException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}

	/**
	 * @throws IllegalArgumentException if p is null
	 */
	public void addWhitelistPattern( Pattern p ) {
		if (p == null) {
		   throw new IllegalArgumentException("Pattern cannot be null");
		}
		whitelistPatterns.add( p );
	}
	
	/**
	 * @throws IllegalArgumentException if pattern is null
	 */
	public void addBlacklistPattern( String pattern ) {
		 if (pattern == null) {
			 throw new IllegalArgumentException("Pattern cannot be null");
		 }
		try {
			blacklistPatterns.add( Pattern.compile( pattern ) );
		} catch( PatternSyntaxException e ) {
			throw new IllegalArgumentException( "Validation misconfiguration, problem with specified pattern: " + pattern, e );
		}
	}

	/**
	 * @throws IllegalArgumentException if p is null
	 */
	public void addBlacklistPattern( Pattern p ) {
		 if (p == null) {
			 throw new IllegalArgumentException("Pattern cannot be null");
		 }
		blacklistPatterns.add( p );
	}
	
	public void setMinimumLength( int length ) {
		minLength = length;
	}
	
	
	public void setMaximumLength( int length ) {
		maxLength = length;
	}

    /**
     * {@inheritDoc}
     */
	public String getValid( String context, String input ) throws ValidationException {
	    if ( StringUtils.isEmpty(input) ) {
			if (allowNull) {
				return null;
	    }
   			throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Input required.", "Input required: context=" + context + "), input=" + input, context );
	    }
	    
	    // canonicalize
	    String canonical = null;
	    try {
	    	canonical = encoder.canonicalize( input );
	    } catch (EncodingException e) {
	        throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Invalid input. Encoding problem detected.", "Error canonicalizing user input", e, context);
	    }

		// check length
		if (canonical.length() < minLength) {
			throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (canonical.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + "), input=" + input, context );
		}

		if (canonical.length() > maxLength) {
			throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (canonical.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + ", input=" + input, context );
		}
		
		// check whitelist patterns
		for (Pattern p : whitelistPatterns) {
			if ( !p.matcher(canonical).matches() ) {
    			throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Invalid input. Please conform to regex " + p.pattern() + ( maxLength == Integer.MAX_VALUE ? "" : " with a maximum length of " + maxLength ), "Invalid input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input, context );
			}
		}
		
		// check blacklist patterns
		for (Pattern p : blacklistPatterns) {
			if ( p.matcher(canonical).matches() ) {
    			throw new ValidationException( this.encoder.encodeForJavaScript(context) + ": Invalid input. Dangerous input matching " + p.pattern() + " detected.", "Dangerous input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input, context );
			}
		}
		
		// validation passed
		return canonical;
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public String sanitize( String context, String input ) {
		return whitelist( input, EncoderConstants.CHAR_ALPHANUMERICS );
	}
	
}

