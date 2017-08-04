package org.owasp.esapi.codecs;

public interface PushbackSequence<T> {

	/**
	 *
	 * @param c
	 */
	void pushback(T c);

	/**
	 * Get the current index of the PushbackString. Typically used in error messages.
	 * @return The current index of the PushbackString.
	 */
	int index();

	/**
	 *
	 * @return
	 */
	boolean hasNext();

	/**
	 *
	 * @return
	 */
	T next();

	/**
	    *
	    * @return
	    */
	T nextHex();

	/**
	   *
	   * @return
	   */
	T nextOctal();

	/**
	 * Return the next character without affecting the current index.
	 * @return
	 */
	T peek();

	/**
	 * Test to see if the next character is a particular value without affecting the current index.
	 * @param c
	 * @return
	 */
	boolean peek(T c);

	/**
	 *
	 */
	void mark();

	/**
	 *
	 */
	void reset();

}