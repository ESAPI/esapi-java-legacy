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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.commons.lang.text.StrTokenizer;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.configuration.EsapiPropertyManager;
import org.owasp.esapi.errors.ConfigurationException;

/**
 * The reference {@code SecurityConfiguration} manages all the settings used by the ESAPI in a single place. In this reference
 * implementation, resources can be put in several locations, which are searched in the following order:
 * <p>
 * 1) Inside a directory set with a call to SecurityConfiguration.setResourceDirectory( "C:\temp\resources" ).
 * <p>
 * 2) Inside the System.getProperty( "org.owasp.esapi.resources" ) directory.
 * You can set this on the java command line as follows (for example):
 * <pre>
 * 		java -Dorg.owasp.esapi.resources="C:\temp\resources"
 * </pre>
 * You may have to add this to the start-up script that starts your web server. For example, for Tomcat,
 * in the "catalina" script that starts Tomcat, you can set the JAVA_OPTS variable to the {@code -D} string above.
 * <p>
 * 3) Inside the {@code System.getProperty( "user.home" ) + "/.esapi"} directory (supported for backward compatibility) or
 * inside the {@code System.getProperty( "user.home" ) + "/esapi"} directory.
 * <p>
 * 4) The first ".esapi" or "esapi" directory on the classpath. (The former for backward compatibility.)
 * <p>
 * Once the Configuration is initialized with a resource directory, you can edit it to set things like master
 * keys and passwords, logging locations, error thresholds, and allowed file extensions.
 * <p>
 * WARNING: Do not forget to update ESAPI.properties to change the master key and other security critical settings.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim .at. manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @author Kevin Wall (kevin.w.wall .at. gmail.com)
 */

public class DefaultSecurityConfiguration implements SecurityConfiguration {
    private static volatile SecurityConfiguration instance = null;

    public static SecurityConfiguration getInstance() {
        if ( instance == null ) {
            synchronized (DefaultSecurityConfiguration.class) {
                if ( instance == null ) {
                    instance = new DefaultSecurityConfiguration();
                }
            }
        }
        return instance;
    }
    
    private Properties properties = null;
    private String cipherXformFromESAPIProp = null;	// New in ESAPI 2.0
    private String cipherXformCurrent = null;		// New in ESAPI 2.0

	/** The name of the ESAPI property file */
	public static final String DEFAULT_RESOURCE_FILE = "ESAPI.properties";
	
    public static final String REMEMBER_TOKEN_DURATION = "Authenticator.RememberTokenDuration";
    public static final String IDLE_TIMEOUT_DURATION = "Authenticator.IdleTimeoutDuration";
    public static final String ABSOLUTE_TIMEOUT_DURATION = "Authenticator.AbsoluteTimeoutDuration";
    public static final String ALLOWED_LOGIN_ATTEMPTS = "Authenticator.AllowedLoginAttempts";
    public static final String USERNAME_PARAMETER_NAME = "Authenticator.UsernameParameterName";
    public static final String PASSWORD_PARAMETER_NAME = "Authenticator.PasswordParameterName";
    public static final String MAX_OLD_PASSWORD_HASHES = "Authenticator.MaxOldPasswordHashes";

    public static final String ALLOW_MULTIPLE_ENCODING = "Encoder.AllowMultipleEncoding";
    public static final String ALLOW_MIXED_ENCODING	= "Encoder.AllowMixedEncoding";
    public static final String CANONICALIZATION_CODECS = "Encoder.DefaultCodecList";

    public static final String DISABLE_INTRUSION_DETECTION  = "IntrusionDetector.Disable";
    
    public static final String MASTER_KEY = "Encryptor.MasterKey";
    public static final String MASTER_SALT = "Encryptor.MasterSalt";
    public static final String KEY_LENGTH = "Encryptor.EncryptionKeyLength";
    public static final String ENCRYPTION_ALGORITHM = "Encryptor.EncryptionAlgorithm";
    public static final String HASH_ALGORITHM = "Encryptor.HashAlgorithm";
    public static final String HASH_ITERATIONS = "Encryptor.HashIterations";
    public static final String CHARACTER_ENCODING = "Encryptor.CharacterEncoding";
    public static final String RANDOM_ALGORITHM = "Encryptor.RandomAlgorithm";
    public static final String DIGITAL_SIGNATURE_ALGORITHM = "Encryptor.DigitalSignatureAlgorithm";
    public static final String DIGITAL_SIGNATURE_KEY_LENGTH = "Encryptor.DigitalSignatureKeyLength";
    			// ==================================//
    			//		New in ESAPI Java 2.0		 //
    			// ================================= //
    public static final String PREFERRED_JCE_PROVIDER = "Encryptor.PreferredJCEProvider";
    public static final String CIPHER_TRANSFORMATION_IMPLEMENTATION = "Encryptor.CipherTransformation";
    public static final String CIPHERTEXT_USE_MAC = "Encryptor.CipherText.useMAC";
    public static final String PLAINTEXT_OVERWRITE = "Encryptor.PlainText.overwrite";
    public static final String IV_TYPE = "Encryptor.ChooseIVMethod";
    public static final String FIXED_IV = "Encryptor.fixedIV";
    public static final String COMBINED_CIPHER_MODES = "Encryptor.cipher_modes.combined_modes";
    public static final String ADDITIONAL_ALLOWED_CIPHER_MODES = "Encryptor.cipher_modes.additional_allowed";
    public static final String KDF_PRF_ALG = "Encryptor.KDF.PRF";
	public static final String PRINT_PROPERTIES_WHEN_LOADED = "ESAPI.printProperties";

    public static final String WORKING_DIRECTORY = "Executor.WorkingDirectory";
    public static final String APPROVED_EXECUTABLES = "Executor.ApprovedExecutables";

    public static final String FORCE_HTTPONLYSESSION = "HttpUtilities.ForceHttpOnlySession";
    public static final String FORCE_SECURESESSION = "HttpUtilities.SecureSession";
    public static final String FORCE_HTTPONLYCOOKIES = "HttpUtilities.ForceHttpOnlyCookies";
    public static final String FORCE_SECURECOOKIES = "HttpUtilities.ForceSecureCookies";
	public static final String MAX_HTTP_HEADER_SIZE = "HttpUtilities.MaxHeaderSize";
    public static final String UPLOAD_DIRECTORY = "HttpUtilities.UploadDir";
    public static final String UPLOAD_TEMP_DIRECTORY = "HttpUtilities.UploadTempDir";
    public static final String APPROVED_UPLOAD_EXTENSIONS = "HttpUtilities.ApprovedUploadExtensions";
    public static final String MAX_UPLOAD_FILE_BYTES = "HttpUtilities.MaxUploadFileBytes";
    public static final String RESPONSE_CONTENT_TYPE = "HttpUtilities.ResponseContentType";
    public static final String HTTP_SESSION_ID_NAME = "HttpUtilities.HttpSessionIdName";

    public static final String APPLICATION_NAME = "Logger.ApplicationName";
    public static final String LOG_LEVEL = "Logger.LogLevel";
    public static final String LOG_FILE_NAME = "Logger.LogFileName";
    public static final String MAX_LOG_FILE_SIZE = "Logger.MaxLogFileSize";
    public static final String LOG_ENCODING_REQUIRED = "Logger.LogEncodingRequired";
    public static final String LOG_APPLICATION_NAME = "Logger.LogApplicationName";
    public static final String LOG_SERVER_IP = "Logger.LogServerIP";
    public static final String VALIDATION_PROPERTIES = "Validator.ConfigurationFile";
    public static final String VALIDATION_PROPERTIES_MULTIVALUED = "Validator.ConfigurationFile.MultiValued";
    public static final String ACCEPT_LENIENT_DATES = "Validator.AcceptLenientDates";



    /**
	 * The default max log file size is set to 10,000,000 bytes (10 Meg). If the current log file exceeds the current
	 * max log file size, the logger will move the old log data into another log file. There currently is a max of
	 * 1000 log files of the same name. If that is exceeded it will presumably start discarding the oldest logs.
	 */
	public static final int DEFAULT_MAX_LOG_FILE_SIZE = 10000000;
	
    protected final int MAX_REDIRECT_LOCATION = 1000;
    
    /**
     * @deprecated	It is not clear whether this is intended to be the max file name length for the basename(1) of
     *				a file or the max full path name length of a canonical full path name. Since it is not used anywhere
     *				in the ESAPI code it is being deprecated and scheduled to be removed in release 2.1.
     */
    protected final int MAX_FILE_NAME_LENGTH = 1000;	// DISCUSS: Is this for given directory or refer to canonicalized full path name?
    													// Too long if the former! (Usually 255 is limit there.) Hard to tell since not used
    													// here in this class and it's protected, so not sure what it's intent is. It's not
    													// used anywhere in the ESAPI code base. I am going to deprecate it because of this. -kww

    /*
     * Implementation Keys
     */
    public static final String LOG_IMPLEMENTATION = "ESAPI.Logger";
    public static final String AUTHENTICATION_IMPLEMENTATION = "ESAPI.Authenticator";
    public static final String ENCODER_IMPLEMENTATION = "ESAPI.Encoder";
    public static final String ACCESS_CONTROL_IMPLEMENTATION = "ESAPI.AccessControl";
    public static final String ENCRYPTION_IMPLEMENTATION = "ESAPI.Encryptor";
    public static final String INTRUSION_DETECTION_IMPLEMENTATION = "ESAPI.IntrusionDetector";
    public static final String RANDOMIZER_IMPLEMENTATION = "ESAPI.Randomizer";
	public static final String EXECUTOR_IMPLEMENTATION = "ESAPI.Executor";
	public static final String VALIDATOR_IMPLEMENTATION = "ESAPI.Validator";
	public static final String HTTP_UTILITIES_IMPLEMENTATION = "ESAPI.HTTPUtilities";

    /*
     * Default Implementations
     */
    public static final String DEFAULT_LOG_IMPLEMENTATION = "org.owasp.esapi.reference.JavaLogFactory";
    public static final String DEFAULT_AUTHENTICATION_IMPLEMENTATION = "org.owasp.esapi.reference.FileBasedAuthenticator";
    public static final String DEFAULT_ENCODER_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultEncoder";
    public static final String DEFAULT_ACCESS_CONTROL_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultAccessController";
    public static final String DEFAULT_ENCRYPTION_IMPLEMENTATION = "org.owasp.esapi.reference.crypto.JavaEncryptor";
    public static final String DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultIntrusionDetector";
    public static final String DEFAULT_RANDOMIZER_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultRandomizer";
    public static final String DEFAULT_EXECUTOR_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultExecutor";
    public static final String DEFAULT_HTTP_UTILITIES_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultHTTPUtilities";
    public static final String DEFAULT_VALIDATOR_IMPLEMENTATION = "org.owasp.esapi.reference.DefaultValidator";

    private static final Map<String, Pattern> patternCache = new HashMap<String, Pattern>();

    /*
     * Absolute path to the user.home. No longer includes the ESAPI portion as it used to.
     */
    private static final String userHome = System.getProperty("user.home" );
    /*
     * Absolute path to the customDirectory
     */	// DISCUSS: Implicit assumption here that there is no SecurityManager installed enforcing the
        //			prevention of reading system properties. Otherwise this will fail with SecurityException.
    private static String customDirectory = System.getProperty("org.owasp.esapi.resources");
    /*
     * Relative path to the resourceDirectory. Relative to the classpath.
     * Specifically, ClassLoader.getResource(resourceDirectory + filename) will
     * be used to load the file.
     */
    private String resourceDirectory = ".esapi";	// For backward compatibility (vs. "esapi")
	private final String resourceFile;
    private EsapiPropertyManager esapiPropertyManager;

//    private static long lastModified = -1;

    /**
     * Instantiates a new configuration, using the provided property file name
     * 
     * @param resourceFile The name of the property file to load
     */
    DefaultSecurityConfiguration(String resourceFile) {
    	this.resourceFile = resourceFile;
        this.esapiPropertyManager = new EsapiPropertyManager();
    	// load security configuration
    	try {
        	loadConfiguration();
        	this.setCipherXProperties();
        } catch( IOException e ) {
	        logSpecial("Failed to load security configuration", e );
	        throw new ConfigurationException("Failed to load security configuration", e);
        }
    }
    
    /**
     * Instantiates a new configuration with the supplied properties.
     * 
     * Warning - if the setResourceDirectory() method is invoked the properties will
     * be re-loaded, replacing the supplied properties.
     * 
     * @param properties
     */
    public DefaultSecurityConfiguration(Properties properties) {
    	resourceFile = DEFAULT_RESOURCE_FILE;
    	this.properties = properties; 
    	this.setCipherXProperties();
    }
    
    /**
     * Instantiates a new configuration.
     */
    public DefaultSecurityConfiguration(){
    	this(DEFAULT_RESOURCE_FILE);
    }
    private void setCipherXProperties() {
		// TODO: FUTURE: Replace by future CryptoControls class???
		// See SecurityConfiguration.setCipherTransformation() for
		// explanation of this.
        // (Propose this in 2.1 via future email to ESAPI-DEV list.)
		cipherXformFromESAPIProp =
			getESAPIProperty(CIPHER_TRANSFORMATION_IMPLEMENTATION,
							 "AES/CBC/PKCS5Padding");
		cipherXformCurrent = cipherXformFromESAPIProp;
    }

    /**
	 * {@inheritDoc}
	 */
    public String getApplicationName() {
    	return getESAPIProperty(APPLICATION_NAME, "DefaultName");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getLogImplementation() {
    	return getESAPIProperty(LOG_IMPLEMENTATION, DEFAULT_LOG_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getAuthenticationImplementation() {
    	return getESAPIProperty(AUTHENTICATION_IMPLEMENTATION, DEFAULT_AUTHENTICATION_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getEncoderImplementation() {
    	return getESAPIProperty(ENCODER_IMPLEMENTATION, DEFAULT_ENCODER_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getAccessControlImplementation() {
    	return getESAPIProperty(ACCESS_CONTROL_IMPLEMENTATION, DEFAULT_ACCESS_CONTROL_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getEncryptionImplementation() {
    	return getESAPIProperty(ENCRYPTION_IMPLEMENTATION, DEFAULT_ENCRYPTION_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getIntrusionDetectionImplementation() {
    	return getESAPIProperty(INTRUSION_DETECTION_IMPLEMENTATION, DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getRandomizerImplementation() {
    	return getESAPIProperty(RANDOMIZER_IMPLEMENTATION, DEFAULT_RANDOMIZER_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getExecutorImplementation() {
    	return getESAPIProperty(EXECUTOR_IMPLEMENTATION, DEFAULT_EXECUTOR_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getHTTPUtilitiesImplementation() {
    	return getESAPIProperty(HTTP_UTILITIES_IMPLEMENTATION, DEFAULT_HTTP_UTILITIES_IMPLEMENTATION);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getValidationImplementation() {
    	return getESAPIProperty(VALIDATOR_IMPLEMENTATION, DEFAULT_VALIDATOR_IMPLEMENTATION);
    }


    /**
	 * {@inheritDoc}
	 */
    public byte[] getMasterKey() {
    	byte[] key = getESAPIPropertyEncoded( MASTER_KEY, null );
    	if ( key == null || key.length == 0 ) {
    		throw new ConfigurationException("Property '" + MASTER_KEY +
    							"' missing or empty in ESAPI.properties file.");
    }
    	return key;
    }

    /**
	 * {@inheritDoc}
	 */
    public void setResourceDirectory( String dir ) {
    	resourceDirectory = dir;
        logSpecial( "Reset resource directory to: " + dir, null );

        // reload configuration if necessary
    	try {
    		this.loadConfiguration();
    	} catch( IOException e ) {
	        logSpecial("Failed to load security configuration from " + dir, e);
    	}
    }

    public int getEncryptionKeyLength() {
    	return getESAPIProperty(KEY_LENGTH, 128 );
    }

    /**
	 * {@inheritDoc}
	 */
    public byte[] getMasterSalt() {
    	byte[] salt = getESAPIPropertyEncoded( MASTER_SALT, null );
    	if ( salt == null || salt.length == 0 ) {
    		throw new ConfigurationException("Property '" + MASTER_SALT +
    							"' missing or empty in ESAPI.properties file.");
    }
    	return salt;
    }

    /**
	 * {@inheritDoc}
	 */
	public List<String> getAllowedExecutables() {
    	String def = "";
        String[] exList = getESAPIProperty(APPROVED_EXECUTABLES,def).split(",");
        return Arrays.asList(exList);
    }

    /**
	 * {@inheritDoc}
	 */
	public List<String> getAllowedFileExtensions() {
    	String def = ".zip,.pdf,.tar,.gz,.xls,.properties,.txt,.xml";
        String[] extList = getESAPIProperty(APPROVED_UPLOAD_EXTENSIONS,def).split(",");
        return Arrays.asList(extList);
    }

    /**
	 * {@inheritDoc}
	 */
    public int getAllowedFileUploadSize() {
        return getESAPIProperty(MAX_UPLOAD_FILE_BYTES, 5000000);
    }


    private Properties loadPropertiesFromStream( InputStream is, String name ) throws IOException {
    	Properties config = new Properties();
        try {
	        config.load(is);
	        logSpecial("Loaded '" + name + "' properties file", null);
        } finally {
            if ( is != null ) try { is.close(); } catch( Exception e ) {}
        }
        return config;
    }

	/**
	 * Load configuration. Never prints properties.
	 * 
	 * @throws java.io.IOException
	 *             if the file is inaccessible
	 */
	protected void loadConfiguration() throws IOException {
		try {
		    //first attempt file IO loading of properties
			logSpecial("Attempting to load " + resourceFile + " via file I/O.");
			properties = loadPropertiesFromStream(getResourceStream(resourceFile), resourceFile);
			
		} catch (Exception iae) {
		    //if file I/O loading fails, attempt classpath based loading next
		    logSpecial("Loading " + resourceFile + " via file I/O failed. Exception was: " + iae);
			logSpecial("Attempting to load " + resourceFile + " via the classpath.");
			try {
				properties = loadConfigurationFromClasspath(resourceFile);
			} catch (Exception e) {				
				logSpecial(resourceFile + " could not be loaded by any means. Fail.", e);
				throw new ConfigurationException(resourceFile + " could not be loaded by any means. Fail.", e);
			}			
		}
		
		// if properties loaded properly above, get validation properties and merge them into the main properties
		if (properties != null) {
			final Iterator<String> validationPropFileNames;
			
			//defaults to single-valued for backwards compatibility
			final boolean multivalued= getESAPIProperty(VALIDATION_PROPERTIES_MULTIVALUED, false);
			final String validationPropValue = getESAPIProperty(VALIDATION_PROPERTIES, "validation.properties");
			
			if(multivalued){
				// the following cast warning goes away if the apache commons lib is updated to current version				
				validationPropFileNames = StrTokenizer.getCSVInstance(validationPropValue);
			} else {
				validationPropFileNames = Collections.singletonList(validationPropValue).iterator();
			}
			
			//clear any cached validation patterns so they can be reloaded from validation.properties
			patternCache.clear();
			while(validationPropFileNames.hasNext()){
				String validationPropFileName = validationPropFileNames.next();
				Properties validationProperties = null;
				try {
				    //first attempt file IO loading of properties
					logSpecial("Attempting to load " + validationPropFileName + " via file I/O.");
					validationProperties = loadPropertiesFromStream(getResourceStream(validationPropFileName), validationPropFileName);
					
				} catch (Exception iae) {
				    //if file I/O loading fails, attempt classpath based loading next
				    logSpecial("Loading " + validationPropFileName + " via file I/O failed.");
					logSpecial("Attempting to load " + validationPropFileName + " via the classpath.");		
					try {
						validationProperties = loadConfigurationFromClasspath(validationPropFileName);
					} catch (Exception e) {				
						logSpecial(validationPropFileName + " could not be loaded by any means. fail.", e);
					}			
				}
				
				if (validationProperties != null) {
			    	Iterator<?> i = validationProperties.keySet().iterator();
			    	while( i.hasNext() ) {
			    		String key = (String)i.next();
			    		String value = validationProperties.getProperty(key);
			    		properties.put( key, value);
			    	}
				}
				
		        if ( shouldPrintProperties() ) {
		    	
		    	//FIXME - make this chunk configurable
		    	/*
		        logSpecial("  ========Master Configuration========", null);
		        //logSpecial( "  ResourceDirectory: " + DefaultSecurityConfiguration.resourceDirectory );
		        Iterator j = new TreeSet( properties.keySet() ).iterator();
		        while (j.hasNext()) {
		            String key = (String)j.next();
		            // print out properties, but not sensitive ones like MasterKey and MasterSalt
		            if ( !key.contains( "Master" ) ) {
		            		logSpecial("  |   " + key + "=" + properties.get(key), null);
		        	}
		        }
		        */
		        }   	
	        }
		}
	}	
	
	/**
	 * @param filename
	 * @return An {@code InputStream} associated with the specified file name as
	 *         a resource stream.
	 * @throws IOException
	 *             If the file cannot be found or opened for reading.
	 */
	public InputStream getResourceStream(String filename) throws IOException {
		if (filename == null) {
			return null;
		}

		try {
			File f = getResourceFile(filename);
			if (f != null && f.exists()) {
				return new FileInputStream(f);
			}
		} catch (Exception e) {
		}

		throw new FileNotFoundException();
	}
	
	/**
	 * {@inheritDoc}
	 */
	public File getResourceFile(String filename) {
		logSpecial("Attempting to load " + filename + " as resource file via file I/O.");

		if (filename == null) {
			logSpecial("Failed to load properties via FileIO. Filename is null.");
			return null; // not found.
		}

		File f = null;

		// first, allow command line overrides. -Dorg.owasp.esapi.resources
		// directory
		f = new File(customDirectory, filename);
		if (customDirectory != null && f.canRead()) {
			logSpecial("Found in 'org.owasp.esapi.resources' directory: " + f.getAbsolutePath());
			return f;
		} else {
			logSpecial("Not found in 'org.owasp.esapi.resources' directory or file not readable: " + f.getAbsolutePath());
		}

		// if not found, then try the programmatically set resource directory
		// (this defaults to SystemResource directory/resourceFile
		URL fileUrl = ClassLoader.getSystemResource(resourceDirectory + "/" + filename);
        if ( fileUrl == null ) {
            fileUrl = ClassLoader.getSystemResource("esapi/" + filename);
        }

		if (fileUrl != null) {
			String fileLocation = fileUrl.getFile();
			f = new File(fileLocation);
			if (f.exists()) {
				logSpecial("Found in SystemResource Directory/resourceDirectory: " + f.getAbsolutePath());
				return f;
			} else {
				logSpecial("Not found in SystemResource Directory/resourceDirectory (this should never happen): " + f.getAbsolutePath());
			}
		} else {
			logSpecial("Not found in SystemResource Directory/resourceDirectory: " + resourceDirectory + File.separator + filename);
		}

		// If not found, then try immediately under user's home directory first in
		//		userHome + "/.esapi"		and secondly under
		//		userHome + "/esapi"
		// We look in that order because of backward compatibility issues.
		String homeDir = userHome;
		if ( homeDir == null ) {
			homeDir = "";	// Without this,	homeDir + "/.esapi"	would produce
							// the string		"null/.esapi"		which surely is not intended.
		}
		// First look under ".esapi" (for reasons of backward compatibility).
		f = new File(homeDir + "/.esapi", filename);
		if ( f.canRead() ) {
			logSpecial("[Compatibility] Found in 'user.home' directory: " + f.getAbsolutePath());
			return f;
		} else {
			// Didn't find it under old directory ".esapi" so now look under the "esapi" directory.
			f = new File(homeDir + "/esapi", filename);
			if ( f.canRead() ) {
				logSpecial("Found in 'user.home' directory: " + f.getAbsolutePath());
				return f;
			} else {
				logSpecial("Not found in 'user.home' (" + homeDir + ") directory: " + f.getAbsolutePath());
			}
		}

		// return null if not found
		return null;
	}
	
    /**
     * Used to load ESAPI.properties from a variety of different classpath locations.
     *
     * @param fileName The properties file filename.
     */
	private Properties loadConfigurationFromClasspath(String fileName) throws IllegalArgumentException {
		Properties result = null;
		InputStream in = null;

		ClassLoader[] loaders = new ClassLoader[] {
				Thread.currentThread().getContextClassLoader(),
				ClassLoader.getSystemClassLoader(),
				getClass().getClassLoader() 
		};
		String[] classLoaderNames = {
				"current thread context class loader",
				"system class loader",
				"class loader for DefaultSecurityConfiguration class"
		};

		ClassLoader currentLoader = null;
		for (int i = 0; i < loaders.length; i++) {
			if (loaders[i] != null) {
				currentLoader = loaders[i];
				try {
					// try root
					String currentClasspathSearchLocation = "/ (root)";
					in = loaders[i].getResourceAsStream(DefaultSearchPath.ROOT.toString());
					
					// try resourceDirectory folder
					if (in == null) {
						currentClasspathSearchLocation = resourceDirectory + "/";
						in = currentLoader.getResourceAsStream(DefaultSearchPath.RESOURCE_DIRECTORY.value() + fileName);
					}

					// try .esapi folder. Look here first for backward compatibility.
					if (in == null) {
						currentClasspathSearchLocation = ".esapi/";
						in = currentLoader.getResourceAsStream(DefaultSearchPath.DOT_ESAPI.value() + fileName);
					} 
					
					// try esapi folder (new directory)
					if (in == null) {
						currentClasspathSearchLocation = "esapi/";
						in = currentLoader.getResourceAsStream(DefaultSearchPath.ESAPI.value() + fileName);
					} 
					
					// try resources folder
					if (in == null) {
						currentClasspathSearchLocation = "resources/";
						in = currentLoader.getResourceAsStream(DefaultSearchPath.RESOURCES.value() + fileName);
					}
					
					// try src/main/resources folder
					if (in == null) {
						currentClasspathSearchLocation = "src/main/resources/";
						in = currentLoader.getResourceAsStream(DefaultSearchPath.SRC_MAIN_RESOURCES.value() + fileName);
					}
		
					// now load the properties
					if (in != null) {
						result = new Properties();
						result.load(in); // Can throw IOException
						logSpecial("SUCCESSFULLY LOADED " + fileName + " via the CLASSPATH from '" +
								currentClasspathSearchLocation + "' using " + classLoaderNames[i] + "!");
						break;	// Outta here since we've found and loaded it.
					}
				} catch (Exception e) {
					result = null;
		
				} finally {
					try {
						in.close();
					} catch (Exception e) {
					}
				}
			}
		}

		if (result == null) {
			// CHECKME: This is odd...why not ConfigurationException?
		    throw new IllegalArgumentException("Failed to load " + resourceFile + " as a classloader resource.");
		}

		return result;
	}

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
     * {@code PrintStream} {@code System.out}.
     *
     * @param message The message to send to the console.
     * @param e The error that occurred. (This value printed via {@code e.toString()}.)
     */
    private void logSpecial(String message, Throwable e) {
    	StringBuffer msg = new StringBuffer(message);
    	if (e != null) {
    		msg.append(" Exception was: ").append( e.toString() );
    	}
		System.out.println( msg.toString() );
		// if ( e != null) e.printStackTrace();		// TODO ??? Do we want this?
    }

    /**
     * Used to log errors to the console during the loading of the properties file itself. Can't use
     * standard logging in this case, since the Logger may not be initialized yet. Output is sent to
     * {@code PrintStream} {@code System.out}.
     *
     * @param message The message to send to the console.
     */
    private void logSpecial(String message) {
		System.out.println(message);
    }
    
    /**
	 * {@inheritDoc}
	 */
    public String getPasswordParameterName() {
        return getESAPIProperty(PASSWORD_PARAMETER_NAME, "password");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getUsernameParameterName() {
        return getESAPIProperty(USERNAME_PARAMETER_NAME, "username");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getEncryptionAlgorithm() {
        return getESAPIProperty(ENCRYPTION_ALGORITHM, "AES");
    }

    /**
	 * {@inheritDoc}
	 */
    public String getCipherTransformation() {
    	assert cipherXformCurrent != null : "Current cipher transformation is null";
    	return cipherXformCurrent;
    }

    /**
     * {@inheritDoc}
     */
    public String setCipherTransformation(String cipherXform) {
    	String previous = getCipherTransformation();
    	if ( cipherXform == null ) {
    		// Special case... means set it to original value from ESAPI.properties
    		cipherXformCurrent = cipherXformFromESAPIProp;
    	} else {
    		assert ! cipherXform.trim().equals("") :
    			"Cipher transformation cannot be just white space or empty string";
    		cipherXformCurrent = cipherXform;	// Note: No other sanity checks!!!
    	}
    	return previous;
    }

    /**
     * {@inheritDoc}
     */
    public boolean useMACforCipherText() {
    	return getESAPIProperty(CIPHERTEXT_USE_MAC, true);
    }

    /**
     * {@inheritDoc}
     */
    public boolean overwritePlainText() {
    	return getESAPIProperty(PLAINTEXT_OVERWRITE, true);
    }
    
    /**
	 * {@inheritDoc}
	 */
    public String getIVType() {
    	String value = getESAPIProperty(IV_TYPE, "random");
    	if ( value.equalsIgnoreCase("fixed") || value.equalsIgnoreCase("random") ) {
    		return value;
    	} else if ( value.equalsIgnoreCase("specified") ) {
    		// This is planned for future implementation where setting
    		// Encryptor.ChooseIVMethod=specified   will require setting some
    		// other TBD property that will specify an implementation class that
    		// will generate appropriate IVs. The intent of this would be to use
    		// such a class with various feedback modes where it is imperative
    		// that for a given key, any particular IV is *NEVER* reused. For
    		// now, we will assume that generating a random IV is usually going
    		// to be sufficient to prevent this.
    		throw new ConfigurationException("'" + IV_TYPE + "=specified' is not yet implemented. Use 'fixed' or 'random'");
    	} else {
    		// TODO: Once 'specified' is legal, adjust exception msg, below.
    		// DISCUSS: Could just log this and then silently return "random" instead.
    		throw new ConfigurationException(value + " is illegal value for " + IV_TYPE +
    										 ". Use 'random' (preferred) or 'fixed'.");
    	}
    }

    /**
	 * {@inheritDoc}
	 */
    public String getFixedIV() {
    	if ( getIVType().equalsIgnoreCase("fixed") ) {
    		String ivAsHex = getESAPIProperty(FIXED_IV, ""); // No default
    		if ( ivAsHex == null || ivAsHex.trim().equals("") ) {
    			throw new ConfigurationException("Fixed IV requires property " +
    						FIXED_IV + " to be set, but it is not.");
    		}
    		return ivAsHex;		// We do no further checks here as we have no context.
    	} else {
    		// DISCUSS: Should we just log a warning here and return null instead?
    		//			If so, may cause NullPointException somewhere later.
    		throw new ConfigurationException("IV type not 'fixed' (set to '" +
    										 getIVType() + "'), so no fixed IV applicable.");
    	}
    }

    /**
	 * {@inheritDoc}
	 */
    public String getHashAlgorithm() {
        return getESAPIProperty(HASH_ALGORITHM, "SHA-512");
    }

    /**
	 * {@inheritDoc}
	 */
    public int getHashIterations() {
    	return getESAPIProperty(HASH_ITERATIONS, 1024);
    }

    /**
     * {@inheritDoc}
     */
	public String getKDFPseudoRandomFunction() {
		return getESAPIProperty(KDF_PRF_ALG, "HmacSHA256");  // NSA recommended SHA2 or better.
	}

    /**
	 * {@inheritDoc}
	 */
    public String getCharacterEncoding() {
        return getESAPIProperty(CHARACTER_ENCODING, "UTF-8");
    }

    /**
	 * {@inheritDoc}
	 */
	public boolean getAllowMultipleEncoding() {
		return getESAPIProperty( ALLOW_MULTIPLE_ENCODING, false );
	}

    /**
	 * {@inheritDoc}
	 */
	public boolean getAllowMixedEncoding() {
		return getESAPIProperty( ALLOW_MIXED_ENCODING, false );
	}

    /**
	 * {@inheritDoc}
	 */
	public List<String> getDefaultCanonicalizationCodecs() {
		List<String> def = new ArrayList<String>();
		def.add( "org.owasp.esapi.codecs.HTMLEntityCodec" );
		def.add( "org.owasp.esapi.codecs.PercentCodec" );
		def.add( "org.owasp.esapi.codecs.JavaScriptCodec" );
		return getESAPIProperty( CANONICALIZATION_CODECS, def );
	}

    /**
	 * {@inheritDoc}
	 */
    public String getDigitalSignatureAlgorithm() {
        return getESAPIProperty(DIGITAL_SIGNATURE_ALGORITHM, "SHAwithDSA");
    }

    /**
	 * {@inheritDoc}
	 */
    public int getDigitalSignatureKeyLength() {
        return getESAPIProperty(DIGITAL_SIGNATURE_KEY_LENGTH, 1024);
    }

    /**
	 * {@inheritDoc}
	 */
    public String getRandomAlgorithm() {
        return getESAPIProperty(RANDOM_ALGORITHM, "SHA1PRNG");
    }

    /**
	 * {@inheritDoc}
	 */
    public int getAllowedLoginAttempts() {
        return getESAPIProperty(ALLOWED_LOGIN_ATTEMPTS, 5);
    }

    /**
	 * {@inheritDoc}
	 */
    public int getMaxOldPasswordHashes() {
        return getESAPIProperty(MAX_OLD_PASSWORD_HASHES, 12);
    }

    /**
	 * {@inheritDoc}
	 */
    public File getUploadDirectory() {
    	String dir = getESAPIProperty( UPLOAD_DIRECTORY, "UploadDir");
    	return new File( dir );
    }

    /**
	 * {@inheritDoc}
	 */
    public File getUploadTempDirectory() {
    	String dir = getESAPIProperty(UPLOAD_TEMP_DIRECTORY,
            System.getProperty("java.io.tmpdir","UploadTempDir"));
    	return new File( dir );
    }
    
    /**
	 * {@inheritDoc}
	 */
	public boolean getDisableIntrusionDetection() {
    	String value = properties.getProperty( DISABLE_INTRUSION_DETECTION );
    	if ("true".equalsIgnoreCase(value)) return true;
    	return false;	// Default result
	}

    /**
	 * {@inheritDoc}
	 */
	public Threshold getQuota(String eventName) {
        int count = getESAPIProperty("IntrusionDetector." + eventName + ".count", 0);
        int interval =  getESAPIProperty("IntrusionDetector." + eventName + ".interval", 0);
        List<String> actions = new ArrayList<String>();
        String actionString = getESAPIProperty("IntrusionDetector." + eventName + ".actions", "");
        if (actionString != null) {
            String[] actionList = actionString.split(",");
            actions = Arrays.asList(actionList);
        }
        if ( count > 0 && interval > 0 && actions.size() > 0 ) {
        	return new Threshold(eventName, count, interval, actions);
        }
        return null;
    }

    /**
	 * {@inheritDoc}
	 */
    public int getLogLevel() {
        String level = getESAPIProperty(LOG_LEVEL, "WARNING" );

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
        logSpecial("The LOG-LEVEL property in the ESAPI properties file has the unrecognized value: " + level + ". Using default: WARNING", null);
        return Logger.WARNING;  // Note: The default logging level is WARNING.
    }

    /**
	 * {@inheritDoc}
	 */
    public String getLogFileName() {
    	return getESAPIProperty( LOG_FILE_NAME, "ESAPI_logging_file" );
    }

	/**
	 * {@inheritDoc}
	 */
    public int getMaxLogFileSize() {
    	return getESAPIProperty( MAX_LOG_FILE_SIZE, DEFAULT_MAX_LOG_FILE_SIZE );
    }
    
    /**
	 * {@inheritDoc}
	 */
    public boolean getLogEncodingRequired() {
    	return getESAPIProperty( LOG_ENCODING_REQUIRED, false );
	}


    /**
	 * {@inheritDoc}
	 */
    public boolean getLogApplicationName() {
    	return getESAPIProperty( LOG_APPLICATION_NAME, true );
	}


    /**
	 * {@inheritDoc}
	 */
    public boolean getLogServerIP() {
    	return getESAPIProperty( LOG_SERVER_IP, true );
	}

    /**
	 * {@inheritDoc}
	 */
    public boolean getForceHttpOnlySession() {
    	return getESAPIProperty( FORCE_HTTPONLYSESSION, true );
    }

    /**
	 * {@inheritDoc}
	 */
    public boolean getForceSecureSession() {
    	return getESAPIProperty( FORCE_SECURESESSION, true );
    }

    /**
	 * {@inheritDoc}
	 */
    public boolean getForceHttpOnlyCookies() {
    	return getESAPIProperty( FORCE_HTTPONLYCOOKIES, true );
    }

    /**
	 * {@inheritDoc}
	 */
    public boolean getForceSecureCookies() {
    	return getESAPIProperty( FORCE_SECURECOOKIES, true );
    }

    /**
	 * {@inheritDoc}
	 */
	public int getMaxHttpHeaderSize() {
        return getESAPIProperty( MAX_HTTP_HEADER_SIZE, 4096);
	}

    /**
	 * {@inheritDoc}
	 */
	public String getResponseContentType() {
        return getESAPIProperty( RESPONSE_CONTENT_TYPE, "text/html; charset=UTF-8" );
    }

	/**
	 * {@inheritDoc}
	 */
	public String getHttpSessionIdName() {
        return getESAPIProperty( HTTP_SESSION_ID_NAME, "JSESSIONID" );
    }
	
	/**
	 * {@inheritDoc}
	 */
    public long getRememberTokenDuration() {
        int days = getESAPIProperty( REMEMBER_TOKEN_DURATION, 14 );
        return (long) (1000 * 60 * 60 * 24 * days);
    }

    /**
	 * {@inheritDoc}
	 */
	public int getSessionIdleTimeoutLength() {
        int minutes = getESAPIProperty( IDLE_TIMEOUT_DURATION, 20 );
        return 1000 * 60 * minutes;
	}

	/**
	 * {@inheritDoc}
	 */
	public int getSessionAbsoluteTimeoutLength() {
        int minutes = getESAPIProperty(ABSOLUTE_TIMEOUT_DURATION, 20 );
        return 1000 * 60 * minutes;
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
    	String value = getESAPIProperty( "Validator." + key, "" );
    	// check cache
    	Pattern p = patternCache.get( value );
    	if ( p != null ) return p;

    	// compile a new pattern
    	if ( value == null || value.equals( "" ) ) return null;
    	try {
    		Pattern q = Pattern.compile(value);
    		patternCache.put( value, q );
    		return q;
    	} catch ( PatternSyntaxException e ) {
    		logSpecial( "SecurityConfiguration for " + key + " not a valid regex in ESAPI.properties. Returning null", null );
    		return null;
    	}
    }

    /**
     * getWorkingDirectory returns the default directory where processes will be executed
     * by the Executor.
     */
	public File getWorkingDirectory() {
		String dir = getESAPIProperty( WORKING_DIRECTORY, System.getProperty( "user.dir") );
		if ( dir != null ) {
			return new File( dir );
		}
		return null;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public String getPreferredJCEProvider() {
	    return properties.getProperty(PREFERRED_JCE_PROVIDER); // No default!
	}  

	/**
	 * {@inheritDoc}
	 */
	public List<String> getCombinedCipherModes()
	{
	    List<String> empty = new ArrayList<String>();     // Default is empty list
	    return getESAPIProperty(COMBINED_CIPHER_MODES, empty);
	}

	/**
	 * {@inheritDoc}
	 */
	public List<String> getAdditionalAllowedCipherModes()
	{
	    List<String> empty = new ArrayList<String>();     // Default is empty list
	    return getESAPIProperty(ADDITIONAL_ALLOWED_CIPHER_MODES, empty);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public boolean getLenientDatesAccepted() {
		return getESAPIProperty( ACCEPT_LENIENT_DATES, false);
	}

	protected String getESAPIProperty( String key, String def ) {
		String value = properties.getProperty(key);
		if ( value == null ) {
    		logSpecial( "SecurityConfiguration for " + key + " not found in ESAPI.properties. Using default: " + def, null );
    		return def;
		}
		return value;
	}

	protected boolean getESAPIProperty( String key, boolean def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
    		logSpecial( "SecurityConfiguration for " + key + " not found in ESAPI.properties. Using default: " + def, null );
    		return def;
		}
		if ( property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes" ) ) {
			return true;
		}
		if ( property.equalsIgnoreCase("false") || property.equalsIgnoreCase( "no" ) ) {
			return false;
		}
		logSpecial( "SecurityConfiguration for " + key + " not either \"true\" or \"false\" in ESAPI.properties. Using default: " + def, null );
		return def;
	}

	protected byte[] getESAPIPropertyEncoded( String key, byte[] def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
    		logSpecial( "SecurityConfiguration for " + key + " not found in ESAPI.properties. Using default: " + def, null );
    		return def;
		}
        try {
            return ESAPI.encoder().decodeFromBase64(property);
        } catch( IOException e ) {
    		logSpecial( "SecurityConfiguration for " + key + " not properly Base64 encoded in ESAPI.properties. Using default: " + def, null );
            return null;
        }
	}

	protected int getESAPIProperty( String key, int def ) {
		String property = properties.getProperty(key);
		if ( property == null ) {
    		logSpecial( "SecurityConfiguration for " + key + " not found in ESAPI.properties. Using default: " + def, null );
    		return def;
		}
		try {
            return Integer.parseInt( property );
		} catch( NumberFormatException e ) {
    		logSpecial( "SecurityConfiguration for " + key + " not an integer in ESAPI.properties. Using default: " + def, null );
			return def;
		}
	}

	/**
     * Returns a {@code List} representing the parsed, comma-separated property.
     * 
	 * @param key  The specified property name
	 * @param def  A default value for the property name to return if the property
	 *             is not set.
	 * @return A list of strings.
	 */
	protected List<String> getESAPIProperty( String key, List<String> def ) {
	    String property = properties.getProperty( key );
	    if ( property == null ) {
	        logSpecial( "SecurityConfiguration for " + key + " not found in ESAPI.properties. Using default: " + def, null );
	        return def;
	    }
	    String[] parts = property.split(",");
	    return Arrays.asList( parts );
	}

    /**
     * {@inheritDoc}
     * Looks for property in three configuration files in following order:
     * 1.) In file defined as org.owasp.esapi.opsteam system property 
     * 2.) In file defined as org.owasp.esapi.devteam system property 
     * 3.) In ESAPI.properties* 
     */
    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        try {
            return esapiPropertyManager.getIntProp(propertyName);
        } catch (ConfigurationException ex) {
            String property = properties.getProperty(propertyName);
            try {
                return Integer.parseInt(property);
            } catch (NumberFormatException e) {
                throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " has incorrect " +
                        "type");
            }
        }
    }

    /**
     * {@inheritDoc}
     * Looks for property in three configuration files in following order:
     * 1.) In file defined as org.owasp.esapi.opsteam system property 
     * 2.) In file defined as org.owasp.esapi.devteam system property 
     * 3.) In ESAPI.properties
     */
    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        try {
            return esapiPropertyManager.getByteArrayProp(propertyName);
        } catch (ConfigurationException ex) {
            String property = properties.getProperty(propertyName);
            if ( property == null ) {
                throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " not found in ESAPI.properties");
            }
            try {
                return ESAPI.encoder().decodeFromBase64(property);
            } catch( IOException e ) {
                throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " has incorrect " +
                        "type");
            }
        }
    }

    /**
     * {@inheritDoc}  
     * Looks for property in three configuration files in following order:
     * 1.) In file defined as org.owasp.esapi.opsteam system property 
     * 2.) In file defined as org.owasp.esapi.devteam system property 
     * 3.) In ESAPI.properties
     */
    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        try {
            return esapiPropertyManager.getBooleanProp(propertyName);
        } catch (ConfigurationException ex) {
            String property = properties.getProperty( propertyName );
            if ( property == null ) {
                throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " not found in ESAPI.properties");
            }
            if ( property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes" ) ) {
                return true;
            }
            if ( property.equalsIgnoreCase("false") || property.equalsIgnoreCase( "no" ) ) {
                return false;
            }
            throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " has incorrect " +
                    "type");
        }
    }

    /**
     * {@inheritDoc}
     * Looks for property in three configuration files in following order:
     * 1.) In file defined as org.owasp.esapi.opsteam system property
     * 2.) In file defined as org.owasp.esapi.devteam system property
     * 3.) In ESAPI.properties
     */
    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        try {
            return esapiPropertyManager.getStringProp(propertyName);
        } catch (ConfigurationException ex) {
            String property = properties.getProperty( propertyName );
            if ( property == null ) {
                throw new ConfigurationException( "SecurityConfiguration for " + propertyName + " not found in ESAPI.properties");
            }
            return property;
        }
    }


    protected boolean shouldPrintProperties() {
        return getESAPIProperty(PRINT_PROPERTIES_WHEN_LOADED, false);
	}

    protected Properties getESAPIProperties() {
        return properties;
    }
    
    public enum DefaultSearchPath {
    	
    	RESOURCE_DIRECTORY("resourceDirectory/"),
    	SRC_MAIN_RESOURCES("src/main/resources/"),
    	ROOT("/"),
    	DOT_ESAPI(".esapi/"),
    	ESAPI("esapi/"),
    	RESOURCES("resources/");
    	
    	private final String path;
    	
    	private DefaultSearchPath(String s){
    		this.path = s;
    	}
    	
    	public String value(){
    		return path;
    	}
    }
}
