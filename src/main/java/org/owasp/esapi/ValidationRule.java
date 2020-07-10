package org.owasp.esapi;

import java.util.Set;

import org.owasp.esapi.errors.ValidationException;

public interface ValidationRule {

	/**
	 * Parse the input, throw exceptions if validation fails
	 * 
	 * @param context
	 *            for logging
	 * @param input
	 *            the value to be parsed
	 * @return a validated value
	 * @throws ValidationException
	 *             if any validation rules fail, <i>except</i> if the
     *             <b>{@code ESAPI.properties}></b> property
     *             "Validator.ValidationRule.getValid.ignore509Fix" is set to
     *             {@code true}, which is the default behavior for ESAPI 2.x
     *             releases. See ESAPI GitHub Issues
     *             <a href="https://github.com/ESAPI/esapi-java-legacy/issues/509}>509</a>
     *             and <a href="https://github.com/ESAPI/esapi-java-legacy/issues/521">521</a>
     *             for futher details.
     *
     * @see #getValid(String context, String input, ValidationErrorList errorList)
	 */
	Object getValid(String context, String input)
			throws ValidationException;

	/**
	 * Whether or not a valid valid can be null. {@code getValid} will throw an
	 * Exception and {#code getSafe} will return the default value if flag is set to
	 * true
	 * 
	 * @param flag
	 *            whether or not null values are valid/safe
	 */
	void setAllowNull(boolean flag);

	/**
	 * Programmatically supplied name for the validator
	 * @return a name, describing the validator
	 */
	String getTypeName();

	/**
	 * @param typeName a name, describing the validator
	 */
	void setTypeName(String typeName);

	/**
	 * @param encoder the encoder to use
	 */
	void setEncoder(Encoder encoder);

	/**
	 * Check if the input is valid, throw an Exception otherwise 
	 */
	void assertValid(String context, String input)
			throws ValidationException;

	/**
	 * Get a validated value, add the errors to an existing error list
	 */
	Object getValid(String context, String input,
			ValidationErrorList errorList) throws ValidationException;

	/**
	 * Try to call {@code getvalid}, then call a 'sanitize' method for sanitization (if one exists),
     * finally return a default value.
	 */
	Object getSafe(String context, String input);
	
	/**
	 * @return true if the input passes validation
	 */
	boolean isValid(String context, String input);

	/**
	 * String the input of all chars contained in the list
	 */
	String whitelist(String input, char[] list);
	
	/**
	 * String the input of all chars contained in the list
	 */
	String whitelist(String input, Set<Character> list);

}
