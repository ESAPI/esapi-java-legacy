package org.owasp.esapi.codecs;


/**
 * The pushback string is used by Codecs to allow them to push decoded characters back onto a string
 * for further decoding. This is necessary to detect double-encoding.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Encoder
 */
public class PushBackSequenceImpl extends AbstractPushbackSequence<Integer>{
    /**
     *
     * @param input
     */
    public PushBackSequenceImpl( String input ) {
		super(input);
	}
	
    /**
     *
     * @return The next value in this Sequence, as an Integer.
     */
    public Integer next() {
		if ( pushback != null ) {
			Integer save = pushback;
			pushback = null;
			return save;
		}
		if ( input == null ) return null;
		if ( input.length() == 0 ) return null;
		if ( index >= input.length() ) return null;
		final Integer point = input.codePointAt(index);
		index += Character.charCount(point);
		return point;
	}
	
    /**
    *
    * @return The next value in this Sequence, as an Integer if it is a hex digit. Null otherwise.
    */
   public Integer nextHex() {
		Integer c = next();
		if ( c == null ) return null;
		if ( isHexDigit( c ) ) return c;
		return null;
	}

   /**
   *
   * @return The next value in this Sequence, as an Integer if it is an octal digit. Null otherwise.
   */
  public Integer nextOctal() {
		Integer c = next();
		if ( c == null ) return null;
		if ( isOctalDigit( c ) ) return c;
		return null;
	}

	  /**
	  * Returns true if the parameter character is a hexidecimal digit 0 through 9, a through f, or A through F.
	  * @param c
	  * @return true if it is a hexidecimal digit, false otherwise.
	  */
	 public static boolean isHexDigit( Integer c ) {
		if ( c == null ) return false;
		Integer ch = Integer.valueOf(c);
		return (ch >= '0' && ch <= '9' ) || (ch >= 'a' && ch <= 'f' ) || (ch >= 'A' && ch <= 'F' );
	}

	 /**
	 * Returns true if the parameter character is an octal digit 0 through 7.
	 * @param c
	 * @return true if it is an octal digit, false otherwise.
	 */
	public static boolean isOctalDigit( Integer c ) {
		if ( c == null ) return false;
		Integer ch = Integer.valueOf(c); 
		return ch >= '0' && ch <= '7';
	}

    /**
     * Return the next codePoint without affecting the current index.
     * @return the next codePoint
     */
    public Integer peek() {
		if ( pushback != null ) return pushback;
		if ( input == null ) return null;
		if ( input.length() == 0 ) return null;
		if ( index >= input.length() ) return null;		
		return input.codePointAt(index);
	}
	
    /**
     * Test to see if the next codePoint is a particular value without affecting the current index.
     * @param c
     * @return if the next value is equal to the supplied value.
     */
    public boolean peek( Integer c ) {
		if ( pushback != null && pushback.intValue() == c ) return true;
		if ( input == null ) return false;
		if ( input.length() == 0 ) return false;
		if ( index >= input.length() ) return false;		
		return input.codePointAt(index) == c;
	}	
	
    /**
     * {@inheritDoc}
     */
    public void mark() {
		temp = pushback;
		mark = index;
	}

    /**
     * {@inheritDoc}
     */
    public void reset() {
		pushback = temp;
		index = mark;
	}
	
    /**
     * {@inheritDoc}
     */
    public String remainder() {
		String output = input.substring( index );
		if ( pushback != null ) {
			output = pushback + output;
		}
		return output;
	}

}
