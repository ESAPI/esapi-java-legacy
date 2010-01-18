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
import java.util.regex.Pattern;

import org.owasp.esapi.Logger;
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
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 */

public class DefaultSecurityConfiguration implements SecurityConfiguration {

    /** The properties. */
    private Properties properties = new Properties();

    /** Regular expression cache */
    private Map regexMap = null;
    
    /** The location of the Resources directory used by ESAPI. */
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

    private static final String IDLE_TIMEOUT_DURATION = "IdleTimeoutDuration";

    private static final String ABSOLUTE_TIMEOUT_DURATION = "AbsoluteTimeoutDuration";
    
    private static final String DISABLE_INTRUSION_DETECTION  = "DisableIntrusionDetection";
    
    private static final String LOG_LEVEL = "LogLevel";
    
    private static final String LOG_FILE_NAME = "LogFileName";

    private static final String MAX_LOG_FILE_SIZE = "MaxLogFileSize";
    
    private static final String LOG_ENCODING_REQUIRED = "LogEncodingRequired";
    
    private static final String LOG_DEFAULT_LOG4J = "LogDefaultLog4J";
    
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
     * where 'path' references the appropriate directory in your system.
     */
    private static String resourceDirectory = System.getProperty(RESOURCE_DIRECTORY);

    private static long lastModified = 0;

    /**
     * Instantiates a new configuration.
     */
    public DefaultSecurityConfiguration() {
        loadConfiguration();
    }

    /**
	 * {@inheritDoc}
	 */
    public String getApplicationName() {
    	return properties.getProperty(APPLICATION_NAME, "AppNameNotSpecified");
    }

    /**
	 * {@inheritDoc}
	 */
    public char[] getMasterPassword() {
        return properties.getProperty(MASTER_PASSWORD).toCharArray();
    }

    /**
	 * {@inheritDoc}
	 */
    public File getKeystore() {
        return new File(getResourceDirectory(), "keystore");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getResourceDirectory() {
    	if (resourceDirectory != null && !resourceDirectory.endsWith( System.getProperty("file.separator"))) {
    		resourceDirectory += System.getProperty("file.separator" );
    	}
    	return resourceDirectory;
    }
            
    /**
	 * {@inheritDoc}
	 */
    public void setResourceDirectory( String dir ) {
    	resourceDirectory = dir;
    	if ( resourceDirectory != null && !resourceDirectory.endsWith( System.getProperty("file.separator"))) {
    		resourceDirectory += System.getProperty("file.separator" );
    	}
    	this.loadConfiguration();
    }
    
    /**
	 * {@inheritDoc}
	 */
    public byte[] getMasterSalt() {
        return properties.getProperty(MASTER_SALT).getBytes();
    }

    /**
	 * {@inheritDoc}
	 */
    public List getAllowedFileExtensions() {
    	String def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
        String[] extList = properties.getProperty(VALID_EXTENSIONS,def).split(",");
        return Arrays.asList(extList);
    }

    /**
	 * {@inheritDoc}
	 */
    public int getAllowedFileUploadSize() {
        String bytes = properties.getProperty(MAX_UPLOAD_FILE_BYTES, "5000000");
        return Integer.parseInt(bytes);
    }

	/**
     * Load ESAPI.properties from the classpath. For easy deployment, 
     * place your ESAPI.properties file in WEB-INF/classes
     */
    private Properties loadConfigurationFromClasspath()
    {
    	ClassLoader loader = getClass().getClassLoader();
    	if ( loader == null ) throw new IllegalArgumentException( "Failure to load ESAPI configuration from classpath");
    	
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
            try { in.close(); } catch (Exception e) {}
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
    		logSpecial("Can't load ESAPI properties from classpath, trying FileIO", ce);
    		file = new File(getResourceDirectory(), "ESAPI.properties");
	        if (file.lastModified() == lastModified)
	            return;
	
	        FileInputStream fis = null;
	        try {
	            fis = new FileInputStream( file );
	            properties.load(fis);
	            logSpecial("Loaded ESAPI properties from " + file.getAbsolutePath(), null);
	        } catch (Exception e) {
	            logSpecial("Can't load ESAPI properties from " + file.getAbsolutePath(), e);
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
            logSpecial("  |   " + key + "=" + properties.get(key), null);
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

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger is not initialized yet.
     *  
     * @param message The message to send to the console.
     * @param e The error that occured (this value is currently ignored).
     */
    private void logSpecial(String message, Throwable e) {
		System.out.println(message);
   }
    
    /**
	 * {@inheritDoc}
	 */
    public String getPasswordParameterName() {
        return properties.getProperty(PASSWORD_PARAMETER_NAME, "password");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getUsernameParameterName() {
        return properties.getProperty(USERNAME_PARAMETER_NAME, "username");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getEncryptionAlgorithm() {
        return properties.getProperty(ENCRYPTION_ALGORITHM, "PBEWithMD5AndDES/CBC/PKCS5Padding");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getHashAlgorithm() {
        return properties.getProperty(HASH_ALGORITHM, "SHA-512");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getCharacterEncoding() {
        return properties.getProperty(CHARACTER_ENCODING, "UTF-8");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getDigitalSignatureAlgorithm() {
        return properties.getProperty(DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getRandomAlgorithm() {
        return properties.getProperty(RANDOM_ALGORITHM, "SHA1PRNG");
    }

    /**
	 * {@inheritDoc}
	 */
    public int getAllowedLoginAttempts() {
        String attempts = properties.getProperty(ALLOWED_LOGIN_ATTEMPTS, "5");
        return Integer.parseInt(attempts);
    }

    /**
	 * {@inheritDoc}
	 */
    public int getMaxOldPasswordHashes() {
        String max = properties.getProperty(MAX_OLD_PASSWORD_HASHES, "12");
        return Integer.parseInt(max);
    }

    /**
	 * {@inheritDoc}
	 */
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

    /**
	 * {@inheritDoc}
	 */
    public int getLogLevel() {
        String level = properties.getProperty(LOG_LEVEL);
        if (level == null) {
// This error is  NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause
// an infinite loop.
            logSpecial("The LOG-LEVEL property in the ESAPI properties file is not defined.", null);
        	return Logger.WARNING;
        }
        if (level.equalsIgnoreCase("OFF"))
            return Logger.OFF;
        if (level.equalsIgnoreCase("FATAL"))
            return Logger.FATAL;
        if (level.equalsIgnoreCase("ERROR"))
            return Logger.ERROR ;
        if (level.equalsIgnoreCase("WARNING"))
            return Logger.WARNING;
        if (level.equalsIgnoreCase("INFO"))
            return Logger.INFO;
        if (level.equalsIgnoreCase("DEBUG"))
            return Logger.DEBUG;
        if (level.equalsIgnoreCase("TRACE"))
            return Logger.TRACE;
        if (level.equalsIgnoreCase("ALL"))
            return Logger.ALL;
        
// This error is NOT logged the normal way because the logger constructor calls getLogLevel() and if this error occurred it would cause
// an infinite loop.
        logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " + level, null);
        return Logger.WARNING;  // Note: The default logging level is WARNING.
    }


    /**
	 * {@inheritDoc}
	 */
    public String getLogFileName() {
    	return properties.getProperty( LOG_FILE_NAME, "ESAPI_logging_file" );
    }

/**
 * The default max log file size is set to 10,000,000 bytes (10 Meg). If the current log file exceeds the current 
 * max log file size, the logger will move the old log data into another log file. There currently is a max of 
 * 1000 log files of the same name. If that is exceeded it will presumably start discarding the oldest logs.
 */
public static final int DEFAULT_MAX_LOG_FILE_SIZE = 10000000;

/**
 * {@inheritDoc}
 */
    public int getMaxLogFileSize() {
    	// The default is 10 Meg if the property is not specified
    	String value = properties.getProperty( MAX_LOG_FILE_SIZE );
    	if (value == null) return DEFAULT_MAX_LOG_FILE_SIZE;
    	
    	try	{
        	return Integer.parseInt(value);	
    	}
    	catch (NumberFormatException e) {
    		return DEFAULT_MAX_LOG_FILE_SIZE;
    	}
    }

    /**
	 * {@inheritDoc}
	 */
    public boolean getLogDefaultLog4J() {
    	String value = properties.getProperty( LOG_DEFAULT_LOG4J );
    	if ( value != null && value.equalsIgnoreCase("true")) return true;
    	return false;	// Default result
	}
    
    /**
	 * {@inheritDoc}
	 */
    public boolean getLogEncodingRequired() {
    	String value = properties.getProperty( LOG_ENCODING_REQUIRED );
    	if ( value != null && value.equalsIgnoreCase("true")) return true;
    	return false;	// Default result
	}

    /**
	 * {@inheritDoc}
	 */
	public String getResponseContentType() {
        return properties.getProperty( RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8" );
    }

	/**
	 * {@inheritDoc}
	 */
    public long getRememberTokenDuration() {
        String value = properties.getProperty( REMEMBER_TOKEN_DURATION, "14" );
        long days = Long.parseLong( value );
        long duration = 1000 * 60 * 60 * 24 * days;
        return duration;
    }
    
    /**
	 * {@inheritDoc}
	 */
	public int getSessionIdleTimeoutLength() {
        String value = properties.getProperty( IDLE_TIMEOUT_DURATION, "20" );
        int minutes = Integer.parseInt( value );
        int duration = 1000 * 60 * minutes;
        return duration;		
	}
	
	/**
	 * {@inheritDoc}
	 */
	public int getSessionAbsoluteTimeoutLength() {
        String value = properties.getProperty( ABSOLUTE_TIMEOUT_DURATION, "120" );
        int minutes = Integer.parseInt( value );
        int duration = 1000 * 60 * minutes;
        return duration;		
	}

   /**
    * getValidationPattern names returns validator pattern names
    * from ESAPI's global properties 
    * 
    * @return 
    * 			a list iterator of pattern names 
    */
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
    
   /**
    * getValidationPattern returns a single pattern based upon key
    * 
    *  @param key 
    *  			validation pattern name you'd like
    *  @return
    *  			if key exists, the associated validation pattern, null otherwise
	*/
    public Pattern getValidationPattern( String key ) {
    	String value = properties.getProperty( "Validator." + key );
    	if ( value == null ) return null;
        Pattern pattern = Pattern.compile(value);
        return pattern;
    }

	public boolean getDisableIntrusionDetection() {
    	String value = properties.getProperty( DISABLE_INTRUSION_DETECTION );
    	if ("true".equalsIgnoreCase(value)) return true;
    	return false;	// Default result
	}
}
