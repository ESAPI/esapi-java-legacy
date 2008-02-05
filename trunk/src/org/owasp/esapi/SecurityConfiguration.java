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
package org.owasp.esapi;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.regex.Pattern;

import org.owasp.esapi.interfaces.ISecurityConfiguration;

/**
 * The SecurityConfiguration manages all the settings used by the ESAPI in a single place. Initializing the
 * Configuration is critically important to getting the ESAPI working properly. You must set a system property before
 * invoking any part of the ESAPI. Here is how to do it:
 * 
 * <PRE>
 * 
 * java -Dorg.owasp.esapi.resources="C:\temp\resources"
 * 
 * </PRE>
 * 
 * You may have to add this to the batch script that starts your web server. For example, in the "catalina" script that
 * starts Tomcat, you can set the JAVA_OPTS variable to the -D string above. Once the Configuration is initialized with
 * a resource directory, you can edit it to set things like master keys and passwords, logging locations, error
 * thresholds, and allowed file extensions.
 * 
 * @author jwilliams
 */

// FIXME: ENHANCE make a getCharacterSet( name );
// FIXME: ENHANCE make character sets configurable
// characterSet.password
// characterSet.globalAllowedCharacterList=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890
// characterSet.makeYourOwnName=
// 
public class SecurityConfiguration implements ISecurityConfiguration {

    /** The properties. */
    private Properties properties = new Properties();

    /** Regular expression cache */
    private Map regexMap = null;
    
    /** The logger. */
    private static final Logger logger = Logger.getLogger("ESAPI", "SecurityConfiguration");

    public static final String RESOURCE_DIRECTORY = "org.owasp.esapi.resources";

    private static final String ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";

    private static final String MASTER_PASSWORD = "MasterPassword";

    private static final String MASTER_SALT = "MasterSalt";

    private static final String VALID_EXTENSIONS = "ValidExtensions";

    private static final String MAX_UPLOAD_FILE_BYTES = "MaxUploadFileBytes";

    private static final String USERNAME_PARAMETER_NAME = "UsernameParameterName";

    private static final String PASSWORD_PARAMETER_NAME = "PasswordParameterName";

    private static final String MAX_OLD_PASSWORD_HASHES = "MaxOldPasswordHashes";

    private static final String ENCRYPTION_ALGORITHM = "EncryptionAlgorithm";

    private static final String HASH_ALGORITHM = "HashAlgorithm";

    private static final String CHARACTER_ENCODING = "CharacterEncoding";

    private static final String RANDOM_ALGORITHM = "RandomAlgorithm";

    private static final String DIGITAL_SIGNATURE_ALGORITHM = "DigitalSignatureAlgorithm";

    private static final String RESPONSE_CONTENT_TYPE = "ResponseContentType";

    private static final String REMEMBER_TOKEN_DURATION = "RememberTokenDuration";

    private static final String LOG_LEVEL = "LogLevel";

    /**
     * Load properties from properties file. Important: This implementation relies on a System property defined when
     * Java is launched. Use:
     * <P>
     *    java -Dorg.owasp.esapi.resources="/path/resources"
     * <P>
     * where path references the appropriate directory in your system.
     */
    private static String resourceDirectory = System.getProperty(RESOURCE_DIRECTORY);

    /** The last modified. */
    private static long lastModified = 0;

    /**
     * Instantiates a new configuration.
     */
    public SecurityConfiguration() {
        // FIXME : this should be reloaded periodically
        loadConfiguration();
    }

    /**
     * Gets the master password.
     * 
     * @return the master password
     */
    public char[] getMasterPassword() {
        return properties.getProperty(MASTER_PASSWORD).toCharArray();
    }

    /**
     * Gets the keystore.
     * 
     * @return the keystore
     */
    public File getKeystore() {
        return new File(getResourceDirectory(), "keystore");
    }

    /**
     * Gets the resource directory.
     * 
     * @return the resource directory
     */
    protected File getResourceDirectory() {
        return new File(resourceDirectory);
    }

    /**
     * Sets the resource directory.
     * 
     * @param dir the new resource directory
     */
    protected void setResourceDirectory(File dir) {
        resourceDirectory = dir.getAbsolutePath();
    }

    /**
     * Gets the master salt.
     * 
     * @return the master salt
     */
    public byte[] getMasterSalt() {
        return properties.getProperty(MASTER_SALT).getBytes();
    }

    /**
     * Gets the allowed file extensions.
     * 
     * @return the allowed file extensions
     */
    public List getAllowedFileExtensions() {
    	String def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
        String[] extList = properties.getProperty(VALID_EXTENSIONS,def).split(",");
        return Arrays.asList(extList);
    }

    /**
     * Gets the allowed file upload size.
     * 
     * @return the allowed file upload size
     */
    public int getAllowedFileUploadSize() {
        String bytes = properties.getProperty(MAX_UPLOAD_FILE_BYTES,"50000");
        return Integer.parseInt(bytes);
    }

    /**
     * Load configuration.
     */
    private void loadConfiguration() {
        File file = new File(getResourceDirectory(), "ESAPI.properties");
        if (file.lastModified() == lastModified)
            return;

        FileInputStream fis = null;
        try {
            fis = new FileInputStream( file );
            properties.load(fis);
            logger.logSpecial("Loaded ESAPI properties from " + file.getAbsolutePath(), null);
        } catch (Exception e) {
            logger.logSpecial("Can't load ESAPI properties from " + file.getAbsolutePath(),e);
        } finally {
            try {
                fis.close();
            } catch (IOException e) {
                // give up
            }
        }

        logger.logSpecial("  ========Master Configuration========", null);
        Iterator i = new TreeSet( properties.keySet() ).iterator();
        while (i.hasNext()) {
            String key = (String) i.next();
            logger.logSpecial("  |   " + key + "=" + properties.get(key),null);
        }
        logger.logSpecial("  ========Master Configuration========", null);
        lastModified = file.lastModified();
        
		// cache regular expressions
		regexMap = new HashMap();

		Iterator regexIterator = getValidationPatternNames();
		while ( regexIterator.hasNext() ) {
			String name = (String)regexIterator.next();
			Pattern regex = getValidationPattern(name);
			if ( name != null && regex != null ) {
				regexMap.put( name, regex );
			}
		}
        
    }

    /**
     * Gets the password parameter name.
     * 
     * @return the password parameter name
     */
    public String getPasswordParameterName() {
        return properties.getProperty(PASSWORD_PARAMETER_NAME,"password");
    }

    /**
     * Gets the username parameter name.
     * 
     * @return the username parameter name
     */
    public String getUsernameParameterName() {
        return properties.getProperty(USERNAME_PARAMETER_NAME,"username");
    }

    /**
     * Gets the encryption algorithm.
     * 
     * @return the algorithm
     */
    public String getEncryptionAlgorithm() {
        return properties.getProperty(ENCRYPTION_ALGORITHM,"PBEWithMD5AndDES/CBC/PKCS5Padding");
    }

    /**
     * Gets the hasing algorithm.
     * 
     * @return the algorithm
     */
    public String getHashAlgorithm() {
        return properties.getProperty(HASH_ALGORITHM,"SHA-512");
    }

    /**
     * Gets the character encoding.
     * 
     * @return encoding name
     */
    public String getCharacterEncoding() {
        return properties.getProperty(CHARACTER_ENCODING,"UTF-8");
    }

    /**
     * Gets the digital signature algorithm.
     * 
     * @return encoding name
     */
    public String getDigitalSignatureAlgorithm() {
        return properties.getProperty(DIGITAL_SIGNATURE_ALGORITHM,"SHAwithDSA");
    }

    /**
     * Gets the random number generation algorithm.
     * 
     * @return encoding name
     */
    public String getRandomAlgorithm() {
        return properties.getProperty(RANDOM_ALGORITHM,"SHA1PRNG");
    }

    /**
     * Gets the allowed login attempts.
     * 
     * @return the allowed login attempts
     */
    public int getAllowedLoginAttempts() {
        String attempts = properties.getProperty(ALLOWED_LOGIN_ATTEMPTS,"5");
        return Integer.parseInt(attempts);
    }

    /**
     * Gets the max old password hashes.
     * 
     * @return the max old password hashes
     */
    public int getMaxOldPasswordHashes() {
        String max = properties.getProperty(MAX_OLD_PASSWORD_HASHES,"12");
        return Integer.parseInt(max);
    }

    // FIXME: ENHANCE should read these quotas into a map and cache them
    public Threshold getQuota(String eventName) {

        int count = 0;
        String countString = properties.getProperty(eventName + ".count");
        if (countString != null) {
            count = Integer.parseInt(countString);
        }

        int interval = 0;
        String intervalString = properties.getProperty(eventName + ".interval");
        if (intervalString != null) {
            interval = Integer.parseInt(intervalString);
        }

        List actions = new ArrayList();
        String actionString = properties.getProperty(eventName + ".actions");
        if (actionString != null) {
            String[] actionList = actionString.split(",");
            actions = Arrays.asList(actionList);
        }

        Threshold q = new Threshold(eventName, count, interval, actions);
        return q;
    }

    // FIXME: ENHANCE integrate log level configuration
    public Level getLogLevel() {
        String level = properties.getProperty(LOG_LEVEL);
        if (level.equalsIgnoreCase("TRACE"))
            return Level.FINER;
        if (level.equalsIgnoreCase("ERROR"))
            return Level.WARNING;
        if (level.equalsIgnoreCase("SEVERE"))
            return Level.SEVERE;
        if (level.equalsIgnoreCase("WARNING"))
            return Level.WARNING;
        if (level.equalsIgnoreCase("SUCCESS"))
            return Level.INFO;
        if (level.equalsIgnoreCase("DEBUG"))
            return Level.CONFIG;
        if (level.equalsIgnoreCase("NONE"))
            return Level.OFF;
        return Level.ALL;
    }

    public String getResponseContentType() {
        String def = "text/html; charset=UTF-8";
        return properties.getProperty( RESPONSE_CONTENT_TYPE, def );
    }

    public long getRememberTokenDuration() {
        String value = properties.getProperty( REMEMBER_TOKEN_DURATION, "14" );
        long days = Long.parseLong( value );
        long duration = 1000 * 60 * 60 * 24 * days;
        return duration;
    }
    
    public Iterator getValidationPatternNames() {
    	TreeSet list = new TreeSet();
    	Iterator i = properties.keySet().iterator();
    	while( i.hasNext() ) {
    		String name = (String)i.next();
    		if ( name.startsWith( "Validator.")) {
    			list.add( name.substring(name.indexOf('.') + 1 ) );
    		}
    	}
    	return list.iterator();
    }
    
    public Pattern getValidationPattern( String key ) {
    	String value = properties.getProperty( "Validator." + key );
    	if ( value == null ) return null;
        Pattern pattern = Pattern.compile(value);
        return pattern;
    }

	public boolean getLogEncodingRequired() {
    	String value = properties.getProperty( "LogEncodingRequired" );
    	if ( value != null && value.equalsIgnoreCase("false")) return false;
    	return true;
	}
}
