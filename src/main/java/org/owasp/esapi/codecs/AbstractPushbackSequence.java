package org.owasp.esapi.codecs;

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
	 *
	 * @param c
	 */
	public void pushback(T c) {
		pushback = c;
	}

	/**
	 * Get the current index of the PushbackString. Typically used in error
	 * messages.
	 * 
	 * @return The current index of the PushbackString.
	 */
	public int index() {
		return index;
	}

	/**
	 *
	 * @return
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
