/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.interfaces;

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
public interface IRandomizer {

	/**
	 * Gets the random string.
	 * 
	 * @param length
	 *            the length
	 * @param characterSet
	 *            the character set
	 * 
	 * @return the random string
	 */
	String getRandomString(int length, char[] characterSet);

	/**
	 * Returns a random boolean.
	 * @return
	 */
	boolean getRandomBoolean();
	
	/**
	 * Gets the random integer.
	 * 
	 * @param min
	 *            the min
	 * @param max
	 *            the max
	 * 
	 * @return the random integer
	 */
	int getRandomInteger(int min, int max);

    /**
     * Returns an unguessable random filename with the specified extension.
     */
    public String getRandomFilename( String extension );
    
    
	/**
	 * Gets the random real.
	 * 
	 * @param min
	 *            the min
	 * @param max
	 *            the max
	 * 
	 * @return the random real
	 */
	float getRandomReal(float min, float max);

    /**
     * Generates a random GUID.
     * @return the GUID
     * @throws EncryptionException 
     */
    String getRandomGUID() throws EncryptionException;
           
}
