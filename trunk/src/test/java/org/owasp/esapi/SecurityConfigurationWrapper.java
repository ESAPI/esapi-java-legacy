package org.owasp.esapi;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Simple wrapper implementation of {@link SecurityConfiguration}. 
 * This allows for easy subclassing and property fixups for unit tests.
 *
 * Note that there are some compilers have issues with Override
 * attributes on methods implementing a interface method with some
 * compilers. Technically Override on such methods is a 1.6 feature so
 * they are commented out here.
 */
public class SecurityConfigurationWrapper implements SecurityConfiguration
{
	private SecurityConfiguration wrapped;

	/**
	 * Constructor wrapping the given configuration.
	 * @param wrapped The configuration to wrap.
	 */
	public SecurityConfigurationWrapper(SecurityConfiguration wrapped)
	{
		this.wrapped = wrapped;
	}

	/**
	 * Access the wrapped configuration.
	 * @return The wrapped configuration.
	 */
	public SecurityConfiguration getWrappedSecurityConfiguration()
	{
		return wrapped;
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getApplicationName()
	{
		return wrapped.getApplicationName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getLogImplementation()
	{
		return wrapped.getLogImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getAuthenticationImplementation()
	{
		return wrapped.getAuthenticationImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncoderImplementation()
	{
		return wrapped.getEncoderImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getAccessControlImplementation()
	{
		return wrapped.getAccessControlImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getIntrusionDetectionImplementation()
	{
		return wrapped.getIntrusionDetectionImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getRandomizerImplementation()
	{
		return wrapped.getRandomizerImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncryptionImplementation()
	{
		return wrapped.getEncryptionImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getValidationImplementation()
	{
		return wrapped.getValidationImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public Pattern getValidationPattern( String typeName )
	{
		return wrapped.getValidationPattern(typeName);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getExecutorImplementation()
	{
		return wrapped.getExecutorImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getHTTPUtilitiesImplementation()
	{
		return wrapped.getHTTPUtilitiesImplementation();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public byte[] getMasterKey()
	{
		return wrapped.getMasterKey();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public File getUploadDirectory()
	{
		return wrapped.getUploadDirectory();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public File getUploadTempDirectory()
	{
		return wrapped.getUploadTempDirectory();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getEncryptionKeyLength()
	{
		return wrapped.getEncryptionKeyLength();
	}
    
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public byte[] getMasterSalt()
	{
		return wrapped.getMasterSalt();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public List getAllowedExecutables()
	{
		return wrapped.getAllowedExecutables();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public List getAllowedFileExtensions()
	{
		return wrapped.getAllowedFileExtensions();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getAllowedFileUploadSize()
	{
		return wrapped.getAllowedFileUploadSize();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getPasswordParameterName()
	{
		return wrapped.getPasswordParameterName();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getUsernameParameterName()
	{
		return wrapped.getUsernameParameterName();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncryptionAlgorithm()
	{
		return wrapped.getEncryptionAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getCipherTransformation()
	{
		return wrapped.getCipherTransformation();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String setCipherTransformation(String cipherXform)
	{
		return wrapped.setCipherTransformation(cipherXform);
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean useMACforCipherText()
	{
		return wrapped.useMACforCipherText();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean overwritePlainText()
	{
		return wrapped.overwritePlainText();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getIVType()
	{
		return wrapped.getIVType();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getFixedIV()
	{
		return wrapped.getFixedIV();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getHashAlgorithm()
	{
		return wrapped.getHashAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getHashIterations()
	{
		return wrapped.getHashIterations();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getCharacterEncoding()
	{
		return wrapped.getCharacterEncoding();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getAllowMultipleEncoding()
	{
		return wrapped.getAllowMultipleEncoding();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public List getDefaultCanonicalizationCodecs()
	{
		return wrapped.getDefaultCanonicalizationCodecs();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getDigitalSignatureAlgorithm()
	{
		return wrapped.getDigitalSignatureAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getDigitalSignatureKeyLength()
	{
		return wrapped.getDigitalSignatureKeyLength();
	}
		   
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getRandomAlgorithm()
	{
		return wrapped.getRandomAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getAllowedLoginAttempts()
	{
		return wrapped.getAllowedLoginAttempts();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getMaxOldPasswordHashes()
	{
		return wrapped.getMaxOldPasswordHashes();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public Threshold getQuota(String eventName)
	{
		return wrapped.getQuota(eventName);
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public File getResourceFile( String filename )
	{
		return wrapped.getResourceFile(filename);
	}
    
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceHttpOnlySession() 
	{
		return wrapped.getForceHttpOnlySession();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceSecureSession() 
	{
		return wrapped.getForceSecureSession();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceHttpOnlyCookies()
	{
		return wrapped.getForceHttpOnlyCookies();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceSecureCookies()
	{
		return wrapped.getForceSecureCookies();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public InputStream getResourceStream( String filename ) throws IOException
	{
		return wrapped.getResourceStream(filename);
	}

    	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public void setResourceDirectory(String dir)
	{
		wrapped.setResourceDirectory(dir);
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getResponseContentType()
	{
		return wrapped.getResponseContentType();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public long getRememberTokenDuration()
	{
		return wrapped.getRememberTokenDuration();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getSessionIdleTimeoutLength()
	{
		return wrapped.getSessionIdleTimeoutLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getSessionAbsoluteTimeoutLength()
	{
		return wrapped.getSessionAbsoluteTimeoutLength();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogEncodingRequired()
	{
		return wrapped.getLogEncodingRequired();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogApplicationName()
	{
		return wrapped.getLogApplicationName();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogServerIP()
	{
		return wrapped.getLogServerIP();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getLogLevel()
	{
		return wrapped.getLogLevel();
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getLogFileName()
	{
		return wrapped.getLogFileName();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getMaxLogFileSize()
	{
	 	return wrapped.getMaxLogFileSize();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public File getWorkingDirectory()
	{
		return wrapped.getWorkingDirectory();
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getDisableIntrusionDetection() {
		return wrapped.getDisableIntrusionDetection();
	}
}
