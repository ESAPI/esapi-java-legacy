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
package org.owasp.esapi;

import org.owasp.esapi.errors.EncryptionException;


/**
 * The IRandomizer interface defines a set of methods for creating
 * cryptographically random numbers and strings. Implementers should be sure to
 * use a strong cryptographic implementation, such as the JCE or BouncyCastle.
 * Weak sources of randomness can undermine a wide variety of security
 * mechanisms.
 * <P>
 * <img src="doc-files/Randomizer.jpg" height="600">
 * <P>
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Randomizer {

	/**
	 * Gets a random string. of a desired length and character set.
	 * 
	 * @param length 
	 * 		the length of the string
	 * @param characterSet 
	 * 		the character set
	 * 
	 * @return the random string
	 */
	String getRandomString(int length, char[] characterSet);

	/**
	 * Returns a random boolean.
	 * 
	 * @return true or false, randomly
	 */
	boolean getRandomBoolean();
	
	/**
	 * Gets the random integer.
	 * 
	 * @param min 
	 * 		the minimum integer that will be returned
	 * @param max 
	 * 		the maximum integer that will be returned
	 * 
	 * @return the random integer
	 */
	int getRandomInteger(int min, int max);

	
	/**
	 * Gets the random long.
	 * 
	 * @return the random long
	 */
    public long getRandomLong();
	
	
    /**
     * Returns an unguessable random filename with the specified extension.
     * @param extenstion 
     * 		extension to add to the random filename
     * 
     * @return a random unguessable filename ending with the specified extension
     */
    public String getRandomFilename( String extension );
    
    
	/**
	 * Gets the random real.
	 * 
	 * @param min 
	 * 		the minimum real number that will be returned
	 * @param max 
	 * 		the maximum real number that will be returned
	 * 
	 * @return the random real
	 */
	float getRandomReal(float min, float max);

    /**
     * Generates a random GUID.
     * 
     * @return the GUID
     * 
     * @throws EncryptionException 
     */
    String getRandomGUID() throws EncryptionException;
           
}
