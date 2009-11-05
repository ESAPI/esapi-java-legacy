/**
 * 
 */
package org.owasp.esapi.util;

import java.util.HashSet;
import java.util.Set;

/**
 * @author Neil Matatall (neil.matatall .at. gmail.com)
 * 
 * Are these necessary?  Are there any libraries or java.lang classes to take
 * care of the conversions?
 * 
 * FIXME: we can convert to using this, but it requires that the array be of Character, not char
 *      new HashSet(Arrays.asList(array))
 * 
 */
public class CollectionsUtil {

	/**
	 * Converts an array of chars to a Set of Characters. 
	 * @param array the contents of the new Set
	 * @return a Set containing the elements in the array
	 */
	public static Set<Character> arrayToSet(char[] array) {
		Set<Character> toReturn = new HashSet<Character>(array.length);
		for (char c : array) {
			toReturn.add(c);
		}
		return toReturn;
	}

	private CollectionsUtil() {
		// prevent instantiation
	}
}
