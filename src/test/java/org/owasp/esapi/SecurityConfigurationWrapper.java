package org.owasp.esapi;

import org.owasp.esapi.errors.ConfigurationException;

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
		return wrapped.getStringProp("Logger.ApplicationName");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getLogImplementation()
	{
		return wrapped.getStringProp("ESAPI.Logger");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getAuthenticationImplementation()
	{
		return wrapped.getStringProp("ESAPI.Authenticator");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncoderImplementation()
	{
		return wrapped.getStringProp("ESAPI.Encoder");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getAccessControlImplementation()
	{
		return wrapped.getStringProp("ESAPI.AccessControl");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getIntrusionDetectionImplementation()
	{
		return wrapped.getStringProp("ESAPI.IntrusionDetector");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getRandomizerImplementation()
	{
		return wrapped.getStringProp("ESAPI.Randomizer");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncryptionImplementation()
	{
		return wrapped.getStringProp("ESAPI.Encryptor");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getValidationImplementation()
	{
		return wrapped.getStringProp("ESAPI.Validator");
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
		return wrapped.getStringProp("ESAPI.Executor");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getHTTPUtilitiesImplementation()
	{
		return wrapped.getStringProp("ESAPI.HTTPUtilities");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public byte[] getMasterKey()
	{
		return wrapped.getByteArrayProp("Encryptor.MasterSalt");
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
		return wrapped.getIntProp("Encryptor.EncryptionKeyLength");
	}
    
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public byte[] getMasterSalt()
	{
		return wrapped.getByteArrayProp("Encryptor.MasterKey");
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
		return wrapped.getIntProp("HttpUtilities.MaxUploadFileBytes");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getPasswordParameterName()
	{
		return wrapped.getStringProp("PasswordParameterName");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getUsernameParameterName()
	{
		return wrapped.getStringProp("Authenticator.UsernameParameterName");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getEncryptionAlgorithm()
	{
		return wrapped.getStringProp("Encryptor.EncryptionAlgorithm");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getCipherTransformation()
	{
		return wrapped.getStringProp("Encryptor.CipherTransformation");
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
		return wrapped.getBooleanProp("Encryptor.CipherText.useMAC");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean overwritePlainText()
	{
		return wrapped.getBooleanProp("Encryptor.PlainText.overwrite");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getIVType()
	{
		return wrapped.getStringProp("Encryptor.ChooseIVMethod");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getFixedIV()
	{
		return wrapped.getStringProp("Encryptor.fixedIV");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getHashAlgorithm()
	{
		return wrapped.getStringProp("Encryptor.HashAlgorithm");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getHashIterations()
	{
		return wrapped.getIntProp("Encryptor.HashIterations");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getCharacterEncoding()
	{
		return wrapped.getStringProp("HttpUtilities.CharacterEncoding");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getAllowMultipleEncoding()
	{
		return wrapped.getBooleanProp("Encoder.AllowMultipleEncoding");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getAllowMixedEncoding()
	{
		return wrapped.getBooleanProp("Encoder.AllowMixedEncoding");
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
		return wrapped.getStringProp("Encryptor.DigitalSignatureAlgorithm");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getDigitalSignatureKeyLength()
	{
		return wrapped.getIntProp("Encryptor.DigitalSignatureKeyLength");
	}
		   
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getRandomAlgorithm()
	{
		return wrapped.getStringProp("Encryptor.RandomAlgorithm");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getAllowedLoginAttempts()
	{
		return wrapped.getIntProp("Authenticator.AllowedLoginAttempts");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getMaxOldPasswordHashes()
	{
		return wrapped.getIntProp("Authenticator.MaxOldPasswordHashes");
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
		return wrapped.getBooleanProp("HttpUtilities.ForceHttpOnlySession");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceSecureSession() 
	{
		return wrapped.getBooleanProp("HttpUtilities.ForceSecureSession");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceHttpOnlyCookies()
	{
		return wrapped.getBooleanProp("HttpUtilities.ForceHttpOnlyCookies");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getForceSecureCookies()
	{
		return wrapped.getBooleanProp("HttpUtilities.ForceSecureCookies");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getMaxHttpHeaderSize() {
        return wrapped.getIntProp("HttpUtilities.MaxHeaderValueSize");
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
		return wrapped.getStringProp("HttpUtilities.ResponseContentType");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getHttpSessionIdName() {
		return wrapped.getStringProp("HttpUtilities.HttpSessionIdName");
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
		return wrapped.getIntProp("HttpUtilities.HTTPJSESSIONIDLENGTH");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getSessionAbsoluteTimeoutLength()
	{
		return wrapped.getIntProp("Authenticator.AbsoluteTimeoutDuration");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogEncodingRequired()
	{
		return wrapped.getBooleanProp("Logger.LogEncodingRequired");
	}
	
	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogApplicationName()
	{
		return wrapped.getBooleanProp("Logger.LogApplicationName");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getLogServerIP()
	{
		return wrapped.getBooleanProp("Logger.LogServerIP");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getLogFileName()
	{
		return wrapped.getStringProp("Logger.LogFileName");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public int getMaxLogFileSize()
	{
	 	return wrapped.getIntProp("Logger.MaxLogFileSize");
	}

	@Override
	public int getIntProp(String propertyName) throws ConfigurationException {
		return wrapped.getIntProp(propertyName);
	}

	@Override
	public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
		return wrapped.getByteArrayProp(propertyName);
	}

	@Override
	public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
		return wrapped.getBooleanProp(propertyName);
	}

	@Override
	public String getStringProp(String propertyName) throws ConfigurationException {
		return wrapped.getStringProp(propertyName);
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
    public List<String> getAdditionalAllowedCipherModes() {
        return wrapped.getAdditionalAllowedCipherModes();
    }

    /**
     * {@inheritDoc}
     */
    // @Override
    public List<String> getCombinedCipherModes() {
        return wrapped.getCombinedCipherModes();
    }

    /**
     * {@inheritDoc}
     */
    public String getPreferredJCEProvider() {
        return wrapped.getStringProp("Encryptor.PreferredJCEProvider");
    }

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public boolean getDisableIntrusionDetection() {
		return wrapped.getBooleanProp("IntrusionDetector.Disable");
	}

	/**
	 * {@inheritDoc}
	 */
	// @Override
	public String getKDFPseudoRandomFunction() {
		return wrapped.getStringProp("Encryptor.KDF.PRF");
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean getLenientDatesAccepted() {
		return wrapped.getBooleanProp("Validator.AcceptLenientDates");
	}
}
