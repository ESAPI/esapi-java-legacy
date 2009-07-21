package org.owasp.esapi;

import org.owasp.esapi.errors.ValidationException;

public interface ValidationRule {

	public abstract Object getValid(String context, String input)
			throws ValidationException;

	public abstract void setAllowNull(boolean flag);

	public abstract String getTypeName();

	public abstract void setTypeName(String typeName);

	public abstract void setEncoder(Encoder encoder);

	public abstract void assertValid(String context, String input)
			throws ValidationException;

	public abstract Object getValid(String context, String input,
			ValidationErrorList errorList) throws ValidationException;

	/**
	 * Return a best-effort safe value even in the case of input errors.
	 * @param context
	 * @param input
	 * @return
	 */
	public abstract Object getSafe(String context, String input);

	public abstract boolean isValid(String context, String input);

	public abstract String whitelist(String input, char[] list);

}