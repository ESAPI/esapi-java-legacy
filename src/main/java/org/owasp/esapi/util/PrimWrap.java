package org.owasp.esapi.util;


/**
 * Standin for possible future caching of primitives in wrapper
 * classes. Currently this does no such thing but it is here to make that
 * possiblity more easy in the future when back porting code that does
 * autoboxing...
 */
public class PrimWrap
{
	/**
	 * Wrap a boolean in a Boolean object.
	 * @param b the boolean to wrap
	 * @return {@link Boolean#TRUE} if b is true.
	 * 	{@link Boolean#FALSE} otherwise.
	 */
	public static Boolean wrapBoolean(boolean b)
	{
		if(b)
			return Boolean.TRUE;
		else
			return Boolean.FALSE;
	}

	/**
	 * Wrap a boolean in a Boolean object.
	 * @param b the boolean to wrap
	 * @return {@link Boolean#TRUE} if b is true.
	 * 	{@link Boolean#FALSE} otherwise.
	 */
	public static Boolean wrapBool(boolean b)
	{
		return wrapBoolean(b);
	}

	/**
	 * Wrap a byte in a Byte object.
	 * @param b the byte to wrap
	 * @return b in a new Byte wrapper.
	 */
	public static Byte wrapByte(byte b)
	{
		return new Byte(b);
	}

	/**
	 * Wrap a short in a Short object.
	 * @param s the short to wrap
	 * @return s in a new Short wrapper.
	 */
	public static Short wrapShort(short s)
	{
		return new Short(s);
	}

	/**
	 * Wrap a char in a Character object.
	 * @param ch the character to wrap
	 * @return ch in a new Character wrapper.
	 */
	public static Character wrapChar(char ch)
	{
		return new Character(ch);
	}

	/**
	 * Wrap a int in a Integer object.
	 * @param i the int to wrap
	 * @return i in a new Integer wrapper.
	 */
	public static Integer wrapInt(int i)
	{
		return new Integer(i);
	}

	/**
	 * Wrap a long in a Long object.
	 * @param l the long to wrap
	 * @return l in a new Long wrapper.
	 */
	public static Long wrapLong(long l)
	{
		return new Long(l);
	}

	/**
	 * Wrap a float in a Float object.
	 * @param f the float to wrap
	 * @return f in a new Float wrapper.
	 */
	public static Float wrapFloat(float f)
	{
		return new Float(f);
	}

	/**
	 * Wrap a double in a Double object.
	 * @param d the double to wrap
	 * @return d in a new Double wrapper.
	 */
	public static Double wrapDouble(double d)
	{
		return new Double(d);
	}
}
