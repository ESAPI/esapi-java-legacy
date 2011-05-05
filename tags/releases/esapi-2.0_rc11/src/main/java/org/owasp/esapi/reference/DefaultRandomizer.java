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
package org.owasp.esapi.reference;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.Randomizer;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a
 * cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Randomizer
 */
public class DefaultRandomizer implements org.owasp.esapi.Randomizer {
    private static volatile Randomizer singletonInstance;

    public static Randomizer getInstance() {
        if ( singletonInstance == null ) {
            synchronized ( DefaultRandomizer.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new DefaultRandomizer();
                }
            }
        }
        return singletonInstance;
    }

    /** The sr. */
    private SecureRandom secureRandom = null;

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("Randomizer");

    private DefaultRandomizer() {
        String algorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
        try {
            secureRandom = SecureRandom.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // Can't throw an exception from the constructor, but this will get
            // it logged and tracked
            new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
        }
    }

    /**
	 * {@inheritDoc}
	 */
    public String getRandomString(int length, char[] characterSet) {
    	StringBuilder sb = new StringBuilder();
        for (int loop = 0; loop < length; loop++) {
            int index = secureRandom.nextInt(characterSet.length);
            sb.append(characterSet[index]);
        }
        String nonce = sb.toString();
        return nonce;
    }

    /**
	 * {@inheritDoc}
	 */
    public boolean getRandomBoolean() {
        return secureRandom.nextBoolean();
    }
    
    /**
	 * {@inheritDoc}
	 */
    public int getRandomInteger(int min, int max) {
        return secureRandom.nextInt(max - min) + min;
    }
    
    /**
	 * {@inheritDoc}
	 */
    public long getRandomLong() {
        return secureRandom.nextLong();    
    }
    
    /**
	 * {@inheritDoc}
	 */
    public float getRandomReal(float min, float max) {
        float factor = max - min;
        return secureRandom.nextFloat() * factor + min;
    }

    /**
	 * {@inheritDoc}
	 */
    public String getRandomFilename(String extension) {
        String fn = getRandomString(12, DefaultEncoder.CHAR_ALPHANUMERICS) + "." + extension;
        logger.debug(Logger.SECURITY_SUCCESS, "Generated new random filename: " + fn );
        return fn;
    }
    
    /**
	 * {@inheritDoc}
	 */
    public String getRandomGUID() throws EncryptionException {
    	return UUID.randomUUID().toString();
    }
    	
    /**
     * {@inheritDoc}
     */
    public byte[] getRandomBytes(int n) {
    	byte[] result = new byte[ n ];
    	secureRandom.nextBytes(result);
    	return result;
    }
    	
}
