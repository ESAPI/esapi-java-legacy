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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncryptionException;

/**
 * Reference implementation of the Randomizer interface. This implementation builds on the JCE provider to provide a
 * cryptographically strong source of entropy. The specific algorithm used is configurable in ESAPI.properties.
 * 
 * @author Jeff Williams
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Randomizer
 */
public class DefaultRandomizer implements org.owasp.esapi.Randomizer {

    /** The sr. */
    private SecureRandom secureRandom = null;

    /** The logger. */
    private final Logger logger = ESAPI.getLogger("Randomizer");

    /**
     * Hide the constructor for the Singleton pattern.
     */
    public DefaultRandomizer() {
        String algorithm = ESAPI.securityConfiguration().getRandomAlgorithm();
        try {
            secureRandom = SecureRandom.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            // Can't throw an exception from the constructor, but this will get
            // it logged and tracked
            new EncryptionException("Error creating randomizer", "Can't find random algorithm " + algorithm, e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IRandomizer#getRandomString(int, char[])
     */
    public String getRandomString(int length, char[] characterSet) {
        StringBuffer sb = new StringBuffer();
        for (int loop = 0; loop < length; loop++) {
            int index = secureRandom.nextInt(characterSet.length);
            sb.append(characterSet[index]);
        }
        String nonce = sb.toString();
        return nonce;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IRandomizer#getRandomBoolean()
     */
    public boolean getRandomBoolean() {
        return secureRandom.nextBoolean();
    }
    
    
    /**
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.Randomizer#getRandomInteger(int, int)
     */
    public int getRandomInteger(int min, int max) {
        return secureRandom.nextInt(max - min) + min;
    }
    
    
    /**
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.Randomizer#getRandomLong()
     */
    public long getRandomLong() {
        return secureRandom.nextLong();    
    }

    
    /*
     * (non-Javadoc)
     * 
     * @see org.owasp.esapi.interfaces.IRandomizer#getRandomReal(float, float)
     */
    public float getRandomReal(float min, float max) {
        float factor = max - min;
        return secureRandom.nextFloat() * factor + min;
    }

    /**
     * Returns an unguessable random filename with the specified extension.
     */
    public String getRandomFilename(String extension) {
        return this.getRandomString(12, DefaultEncoder.CHAR_ALPHANUMERICS) + "." + extension;
    }

    public String getRandomGUID() throws EncryptionException {
        // create random string to seed the GUID
        StringBuffer sb = new StringBuffer();
        try {
            sb.append(InetAddress.getLocalHost().toString());
        } catch (UnknownHostException e) {
            sb.append("0.0.0.0");
        }
        sb.append(":");
        sb.append(Long.toString(System.currentTimeMillis()));
        sb.append(":");
        sb.append(this.getRandomString(20, DefaultEncoder.CHAR_ALPHANUMERICS));

        // hash the random string to get some random bytes
        String hash = ESAPI.encryptor().hash(sb.toString(), "salt");
        byte[] array = null;
        try {
            array = ESAPI.encoder().decodeFromBase64(hash);
        } catch (IOException e) {
            logger.fatal(Logger.SECURITY, "Problem decoding hash while creating GUID: " + hash);
        }
        
        // convert to printable hexadecimal characters 
        StringBuffer hex = new StringBuffer();
        for (int j = 0; j < array.length; ++j) {
            int b = array[j] & 0xFF;
            if (b < 0x10)
                hex.append('0');
            hex.append(Integer.toHexString(b));
        }
        String raw = hex.toString().toUpperCase();

        // convert to standard GUID format
        StringBuffer result = new StringBuffer();
        result.append(raw.substring(0, 8));
        result.append("-");
        result.append(raw.substring(8, 12));
        result.append("-");
        result.append(raw.substring(12, 16));
        result.append("-");
        result.append(raw.substring(16, 20));
        result.append("-");
        result.append(raw.substring(20));
        return result.toString();
    }

}
