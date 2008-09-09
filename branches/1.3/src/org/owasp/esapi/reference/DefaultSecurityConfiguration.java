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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
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

import org.owasp.esapi.SecurityConfiguration;

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

public class DefaultSecurityConfiguration implements SecurityConfiguration {

    /** The properties. */
    private Properties properties = new Properties();

    /** Regular expression cache */
    private Map regexMap = null;
    
    public static final String RESOURCE_DIRECTORY = "org.owasp.esapi.resources";

    private static final String ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";

    private static final String APPLICATION_NAME = "ApplicationName";

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

    
    protected final int MAX_REDIRECT_LOCATION = 1000;
    
    protected final int MAX_FILE_NAME_LENGTH = 1000;
    
    
    /**
     * Load properties from properties file. Set this with setResourceDirectory
     * from your web application or ESAPI filter. For test and non-web applications,
     * this implementation defaults to a System property defined when Java is launched.
     * Use:
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
    public DefaultSecurityConfiguration() {
        loadConfiguration();
    }

    /* (non-Javadoc)
     * @see org.owasp.esapi.interfaces.ISecurityConfiguration#getApplicationName()
     */
    public String getApplicationName() {
    	return properties.getProperty(APPLICATION_NAME);
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
    public String getResourceDirectory() {
    	if ( resourceDirectory != null && !resourceDirectory.endsWith( System.getProperty("file.separator"))) {
    		resourceDirectory += System.getProperty("file.separator" );
    	}
    	return resourceDirectory;
    }
        
    
    public void setResourceDirectory( String dir ) {
    	resourceDirectory = dir;
    	if ( resourceDirectory != null && !resourceDirectory.endsWith( System.getProperty("file.separator"))) {
    		resourceDirectory += System.getProperty("file.separator" );
    	}
    	this.loadConfiguration();
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
     * Load ESAPI.properties from the classpath. For easy deployment, 
     * place your ESAPI.properties file in WEB-INF/classes
     */
    private Properties loadConfigurationFromClasspath()
    {
    	ClassLoader loader = getClass().getClassLoader();

        Properties result = null;
        
        InputStream in = null;
        try {
            in = loader.getResourceAsStream("ESAPI.properties");
            if (in != null) {
                result = new Properties ();
                result.load(in); // Can throw IOException
            }
        } catch (Exception e) {
            result = null;
            
        } finally {
            if (in != null) try { in.close (); } catch (Throwable ignore) {}
        }
        
        if (result == null) {
            throw new IllegalArgumentException ("Can't load ESAPI.properties as a classloader resource");
        }
        
        return result;
    }

    /**
     * Load configuration.
     */
    private void loadConfiguration() {
    	
    	File file = null;
    	
    	try {
    		properties = loadConfigurationFromClasspath();
    		logSpecial("Loaded ESAPI properties from classpath", null);
    		
    	} catch (Exception ce) {
    		logSpecial("Can't load ESAPI properties from classpath, trying FileIO",ce);
    		file = new File(getResourceDirectory(), "ESAPI.properties");
	        if (file.lastModified() == lastModified)
	            return;
	
	        FileInputStream fis = null;
	        try {
	            fis = new FileInputStream( file );
	            properties.load(fis);
	            logSpecial("Loaded ESAPI properties from " + file.getAbsolutePath(), null);
	        } catch (Exception e) {
	            logSpecial("Can't load ESAPI properties from " + file.getAbsolutePath(),e);
	        } finally {
	            try {
	                fis.close();
	            } catch (IOException e) {
	                // give up
	            }
	        }
    	}

        logSpecial("  ========Master Configuration========", null);
        Iterator i = new TreeSet( properties.keySet() ).iterator();
        while (i.hasNext()) {
            String key = (String) i.next();
            logSpecial("  |   " + key + "=" + properties.get(key),null);
        }
        
        if (file != null) {
        	logSpecial("  ========Master Configuration========", null);
        	lastModified = file.lastModified();
        }
        	
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

    private void logSpecial(String message, Throwable e) {
		System.out.println(message);
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
    	if ( value != null && value.equalsIgnoreCase("true")) return true;
    	return false;
	}
}
