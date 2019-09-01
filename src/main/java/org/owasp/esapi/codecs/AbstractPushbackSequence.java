/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2017 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Matt Seil (mseil .at. owasp.org)
 * @created 2017
 * 
 */

package org.owasp.esapi.codecs;

/**
 * This Abstract class provides the generic logic for using a {@link PushbackSequence}
 * in regards to iterating strings.  The final Impl is intended for the user to supply
 * a type T such that the pushback interface can be utilized for sequences
 * of type T.  Presently this generic class is limited by the fact that 
 * input is a String.  
 *  
 * @author Matt Seil
 *
 * @param <T>
 */
public abstract class AbstractPushbackSequence<T> implements PushbackSequence<T> {
	protected String input;
	protected T pushback;
	protected T temp;
	protected int index = 0;
	protected int mark = 0;

	public AbstractPushbackSequence(String input) {
		this.input = input;
	}

	/**
	 * {@inheritDoc}
	 */
	public void pushback(T c) {
		pushback = c;
	}

	/**
	 * {@inheritDoc}
	 */
	public int index() {
		return index;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean hasNext() {
		if (pushback != null)
			return true;
		if (input == null)
			return false;
		if (input.length() == 0)
			return false;
		if (index >= input.length())
			return false;
		return true;
	}
}
