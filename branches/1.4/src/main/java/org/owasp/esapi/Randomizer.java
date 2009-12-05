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
 * The Randomizer interface defines a set of methods for creating
 * cryptographically random numbers and strings. Implementers should be sure to
 * use a strong cryptographic implementation, such as the JCE or BouncyCastle.
 * Weak sources of randomness can undermine a wide variety of security
 * mechanisms. The specific algorithm used is configurable in ESAPI.properties.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Randomizer {

	/**
	 * Gets a random string of a desired length and character set.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * If SecureRandom is not used, the pseudo-random number gernerator used should comply with the 
	 * statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
	 * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.
	 * 
	 * @param length 
	 * 		the length of the string
	 * @param characterSet 
	 * 		the set of characters to include in the created random string
	 * 
	 * @return 
	 * 		the random string of the desired length and character set
	 */
	String getRandomString(int length, char[] characterSet);

	/**
	 * Returns a random boolean.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * If SecureRandom is not used, the pseudo-random number gernerator used should comply with the 
	 * statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
	 * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.
	 * 
	 * @return 
	 * 		true or false, randomly
	 */
	boolean getRandomBoolean();
	
	/**
	 * Gets the random integer. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * If SecureRandom is not used, the pseudo-random number gernerator used should comply with the 
	 * statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
	 * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.
	 * 
	 * @param min 
	 * 		the minimum integer that will be returned
	 * @param max 
	 * 		the maximum integer that will be returned
	 * 
	 * @return 
	 * 		the random integer
	 */
	int getRandomInteger(int min, int max);

	
	/**
	 * Gets the random long. The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * If SecureRandom is not used, the pseudo-random number gernerator used should comply with the 
	 * statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
	 * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.
	 * 
	 * @return 
	 * 		the random long
	 */
    public long getRandomLong();
	
	
    /**
     * Returns an unguessable random filename with the specified extension.  This method could call
     * getRandomString(length, charset) from this Class with the desired length and alphanumerics as the charset 
     * then merely append "." + extension.
     * 
     * @param extension 
     * 		extension to add to the random filename
     * 
     * @return 
     * 		a random unguessable filename ending with the specified extension
     */
    public String getRandomFilename( String extension );
    
    
	/**
	 * Gets the random real.  The use of java.security.SecureRandom
	 * is recommended because it provides a cryptographically strong pseudo-random number generator. 
	 * If SecureRandom is not used, the pseudo-random number gernerator used should comply with the 
	 * statistical random number generator tests specified in <a href="http://csrc.nist.gov/cryptval/140-2.htm">
	 * FIPS 140-2, Security Requirements for Cryptographic Modules</a>, section 4.9.1.
	 * 
	 * @param min 
	 * 		the minimum real number that will be returned
	 * @param max 
	 * 		the maximum real number that will be returned
	 * 
	 * @return 
	 * 		the random real
	 */
	float getRandomReal(float min, float max);

    /**
     * Generates a random GUID.  This method could use a hash of random Strings, the current time,
     * and any other random data available.  The format is a well-defined sequence of 32 hex digits 
     * grouped into chunks of 8-4-4-4-12.  
     * 
     * @return 
     * 		the GUID
     * 
     * @throws 
     * 		EncryptionException if hashing or encryption fails 
     */
    String getRandomGUID() throws EncryptionException;
           
}
