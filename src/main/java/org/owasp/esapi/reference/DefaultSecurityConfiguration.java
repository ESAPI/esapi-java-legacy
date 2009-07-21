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

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;

/**
 * The SecurityConfiguration manages all the settings used by the ESAPI in a single place. In this reference
 * implementation, resources can be put in several locations, which are searched in the following order:
 * <p>
 * 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( "C:\temp\resources" ).
 * <p>
 * 2) Inside the System.getProperty( "org.owasp.esapi.resources" ) directory.
 * You can set this on the java command line
 * as follows (for example): java -Dorg.owasp.esapi.resources="C:\temp\resources". You may have to add this
 * to the batch script that starts your web server. For example, in the "catalina" script that
 * starts Tomcat, you can set the JAVA_OPTS variable to the -D string above.
 * <p>
 * 3) Inside the System.getProperty( "user.home" ) + "/.esapi" directory
 * <p>
 * 4) In an ".esapi" directory on the classpath
 * <p>
 * Once the Configuration is initialized with a resource directory, you can edit it to set things like master
 * keys and passwords, logging locations, error thresholds, and allowed file extensions.
 * <p>
 * WARNING: Do not forget to update ESAPI.properties to change the master key and other security critical settings.
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 */

public class DefaultSecurityConfiguration implements SecurityConfiguration {

    /** The properties. */
    private Properties properties = new Properties();

    /** Regular expression cache */
    private Map regexMap = null;
    
    private static final String ALLOWED_LOGIN_ATTEMPTS = "AllowedLoginAttempts";

    private static final String APPLICATION_NAME = "ApplicationName";

    private static final String MASTER_KEY = "MasterKey";

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
    
    private static final String LOG_LEVEL = "LogLevel";
    
    private static final String LOG_FILE_NAME = "LogFileName";

    private static final String MAX_LOG_FILE_SIZE = "MaxLogFileSize";
    
    private static final String LOG_ENCODING_REQUIRED = "LogEncodingRequired";
        
    /**
     *
     */
    protected final int MAX_REDIRECT_LOCATION = 1000;
    
    /**
     *
     */
    protected final int MAX_FILE_NAME_LENGTH = 1000;
    
    private static String userDirectory = System.getProperty("user.home" ) + "/.esapi";

    private static String customDirectory = System.getProperty("org.owasp.esapi.resources");

    private static String resourceDirectory = null;
    
    private static long lastModified = -1;

    /**
     * Instantiates a new configuration.
     */
    public DefaultSecurityConfiguration() {
    	// load security configuration
    	try {
        	loadConfiguration();
        } catch( IOException e ) {
	        logSpecial("Failed to load security configuration", e );
        }
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
    public byte[] getMasterKey() {
        String encoded = properties.getProperty(MASTER_KEY);
        try {
            return ESAPI.encoder().decodeFromBase64(encoded);
        } catch( IOException e ) {
            return null;
        }
    }

    /**
	 * {@inheritDoc}
	 */
    public File getKeystore() {
        return getResourceFile("keystore");
    }

    
    /**
	 * {@inheritDoc}
	 */
    public void setResourceDirectory( String dir ) {
    	resourceDirectory = dir;
    	if ( resourceDirectory != null && !resourceDirectory.endsWith( System.getProperty("file.separator"))) {
    		resourceDirectory += System.getProperty("file.separator" );
    	}
        logSpecial( "Reset resource directory to: " + dir, null );
     	
        // reload configuration if necessary
    	try {
    		this.loadConfiguration();
    	} catch( IOException e ) {
	        logSpecial("Failed to load security configuration from " + dir, e);
    	}
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

    
    private Properties loadPropertiesFromStream( InputStream is ) throws IOException {
        if ( is == null ) return properties;
    	Properties config = new Properties();
        try {
	        config.load(is);
	        logSpecial("Loaded ESAPI properties", null);
        } finally {
            if ( is != null ) try { is.close(); } catch( Exception e ) {}
        }
        return config;
    }
    

    /**
	 * {@inheritDoc}
     *
     * @param filename
     * @return
     */
    public File getResourceFile( String filename ) {
    	File f = null;
    	logSpecial( "Seeking " + filename, null );
    	
    	// try the programatically set resource directory
    	f = new File( resourceDirectory, filename );
    	if ( resourceDirectory != null && f.exists() ) {
        	logSpecial( "  Found in setResourceDirectory: " + f.getAbsolutePath(), null );
        	return f;
    	} else {
        	logSpecial( "  Not found in setResourceDirectory: " + f.getAbsolutePath(), null );
    	}
    	
    	// if not found, then try the -Dorg.owasp.esapi.resources directory
		f = new File( customDirectory, filename );
    	if ( customDirectory != null && f.exists() ) {
        	logSpecial( "  Found in 'org.owasp.esapi.resources' directory: " + f.getAbsolutePath(), null );
        	return f;
    	} else {
        	logSpecial( "  Not found in 'org.owasp.esapi.resources' directory: " + f.getAbsolutePath(), null );
    	}

    	// if not found, then try the user's home directory
    	f = new File( userDirectory, filename);    		
    	if ( userDirectory != null && f.exists() ) {
        	logSpecial( "  Found in 'user.home' directory: " + f.getAbsolutePath(), null );
        	return f;
    	} else {
        	logSpecial( "  Not found in 'user.home' directory: " + f.getAbsolutePath(), null );
    	}
    	
    	// return null if not found
    	return null;
    }

    
    /**
     * Utility method to get a resource as an InputStream. The search looks for an "esapi-resources" directory in
     * the setResourceDirectory() location, then the System.getProperty( "org.owasp.esapi.resources" ) location,
     * then the System.getProperty( "user.home" ) location, and then the classpath.
     * @param filename
     * @return
     * @throws IOException
     */
    public InputStream getResourceStream( String filename ) throws IOException {
    	InputStream in = null;
    	
    	File f = getResourceFile( filename );
    	if ( f != null ) {
    		// shortcut out if the file hasn't been modified
            if (f.lastModified() == lastModified) {
                lastModified = f.lastModified();
            	return null;
            }
    		in = new FileInputStream( f ); 
    	} else {
	    	ClassLoader loader = getClass().getClassLoader();
	 		in = loader.getResourceAsStream( ".esapi/"+filename );
	 		if ( in != null ) {
	 	    	logSpecial( "  Found on classpath", null );
	 		} else {
	 	    	logSpecial( "  Not found on classpath", null );
	 	    	logSpecial( "  Not found anywhere", null );
	 		}
    	}
    	return in;
    }

    /**
     * Load configuration.
     */
    private void loadConfiguration() throws IOException {
    	properties = loadPropertiesFromStream( getResourceStream( "ESAPI.properties" ) );

        logSpecial("  ========Master Configuration========", null);
        Iterator i = new TreeSet( properties.keySet() ).iterator();
        while (i.hasNext()) {
            String key = (String) i.next();
            logSpecial("  |   " + key + "=" + properties.get(key), null);
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

}
