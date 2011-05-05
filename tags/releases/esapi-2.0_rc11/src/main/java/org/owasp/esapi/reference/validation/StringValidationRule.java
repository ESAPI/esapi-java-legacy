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

import org.owasp.esapi.Encoder;
import org.owasp.esapi.EncoderConstants;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.util.NullSafe;


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
	protected boolean validateInputAndCanonical = true;

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
	 * Set the flag which determines whether the in input itself is
	 * checked as well as the canonical form of the input.
	 * @param flag The value to set
	 */
	public void setValidateInputAndCanonical(boolean flag)
	{
		validateInputAndCanonical = flag;
	}

	/**
	 * checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkWhitelist(String context, String input, String orig) throws ValidationException
	{
		// check whitelist patterns
		for (Pattern p : whitelistPatterns) {
			if ( !p.matcher(input).matches() ) {
				throw new ValidationException( context + ": Invalid input. Please conform to regex " + p.pattern() + ( maxLength == Integer.MAX_VALUE ? "" : " with a maximum length of " + maxLength ), "Invalid input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig,input) ? "" : ", orig=" + orig), context );
			}
		}

		return input;
	}

	/**
	 * checks input against whitelists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkWhitelist(String context, String input) throws ValidationException
	{
		return checkWhitelist(context, input, input);
	}

	/**
	 * checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkBlacklist(String context, String input, String orig) throws ValidationException
	{
		// check blacklist patterns
		for (Pattern p : blacklistPatterns) {
			if ( p.matcher(input).matches() ) {
				throw new ValidationException( context + ": Invalid input. Dangerous input matching " + p.pattern() + " detected.", "Dangerous input: context=" + context + ", type(" + getTypeName() + ")=" + p.pattern() + ", input=" + input + (NullSafe.equals(orig,input) ? "" : ", orig=" + orig), context );
			}
		}

		return input;
	}

	/**
	 * checks input against blacklists.
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkBlacklist(String context, String input) throws ValidationException
	{
		return checkBlacklist(context, input, input);
	}

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkLength(String context, String input, String orig) throws ValidationException
	{
		if (input.length() < minLength) {
			throw new ValidationException( context + ": Invalid input. The minimum length of " + minLength + " characters was not met.", "Input does not meet the minimum length of " + minLength + " by " + (minLength - input.length()) + " characters: context=" + context + ", type=" + getTypeName() + "), input=" + input + (NullSafe.equals(input,orig) ? "" : ", orig=" + orig), context );
		}

		if (input.length() > maxLength) {
			throw new ValidationException( context + ": Invalid input. The maximum length of " + maxLength + " characters was exceeded.", "Input exceeds maximum allowed length of " + maxLength + " by " + (input.length()-maxLength) + " characters: context=" + context + ", type=" + getTypeName() + ", orig=" + orig +", input=" + input, context );
		}

		return input;
	}

	/**
	 * checks input lengths
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkLength(String context, String input) throws ValidationException
	{
		return checkLength(context, input, input);
	}

	/**
	 * checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @param orig A origional input to include in exception
	 *	messages. This is not included if it is the same as
	 *	input.
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkEmpty(String context, String input, String orig) throws ValidationException
	{
		if(!StringUtilities.isEmpty(input))
			return input;
		if(allowNull)
			return null;
		throw new ValidationException( context + ": Input required.", "Input required: context=" + context + "), input=" + input + (NullSafe.equals(input,orig) ? "" : ", orig=" + orig), context );
	}

	/**
	 * checks input emptiness
	 * @param context The context to include in exception messages
	 * @param input the input to check
	 * @return input upon a successful check
	 * @throws ValidationException if the check fails.
	 */
	private String checkEmpty(String context, String input) throws ValidationException
	{
		return checkEmpty(context, input, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getValid( String context, String input ) throws ValidationException
	{
		String data = null;

		// checks on input itself

		// check for empty/null
		if(checkEmpty(context, input) == null)
			return null;

		if (validateInputAndCanonical)
		{
			//first validate pre-canonicalized data
			
			// check length
			checkLength(context, input);

			// check whitelist patterns
			checkWhitelist(context, input);

			// check blacklist patterns
			checkBlacklist(context, input);
			
			// canonicalize
			data = encoder.canonicalize( input );
			
		} else {
			
			//skip canonicalization
			data = input;			
		}

		// check for empty/null
		if(checkEmpty(context, data, input) == null)
			return null;

		// check length
		checkLength(context, data, input);

		// check whitelist patterns
		checkWhitelist(context, data, input);

		// check blacklist patterns
		checkBlacklist(context, data, input);

		// validation passed
		return data;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
		public String sanitize( String context, String input ) {
			return whitelist( input, EncoderConstants.CHAR_ALPHANUMERICS );
		}

}

