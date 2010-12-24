package org.owasp.esapi;

import java.io.File;
import java.util.List;

/**
 * Simple wrapper implementation of {@link SecurityConfiguration}. 
 * This allows for easy subclassing and property fixups for unit tests.
 *
 * This has been changed to be concrete instead of abstract so problems
 * caused by changes to the interface will show up here (ie, not abstract
 * not implementing...) instead of versions inheriting from it.
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

	/** {@inheritDoc} */
	public String getApplicationName()
	{
		return wrapped.getApplicationName();
	}
	
	/** {@inheritDoc} */
	public char[] getMasterPassword()
	{
		return wrapped.getMasterPassword();
	}

	/** {@inheritDoc} */
	public File getKeystore()
	{
		return wrapped.getKeystore();
	}

	/** {@inheritDoc} */
	public byte[] getMasterSalt()
	{
		return wrapped.getMasterSalt();
	}

	/** {@inheritDoc} */
	public List getAllowedFileExtensions()
	{
		return wrapped.getAllowedFileExtensions();
	}

	/** {@inheritDoc} */
	public int getAllowedFileUploadSize()
	{
		return wrapped.getAllowedFileUploadSize();
	}

	/** {@inheritDoc} */
	public String getPasswordParameterName()
	{
		return wrapped.getPasswordParameterName();
	}

	/** {@inheritDoc} */
	public String getUsernameParameterName()
	{
		return wrapped.getUsernameParameterName();
	}

	/** {@inheritDoc} */
	public String getEncryptionAlgorithm()
	{
		return wrapped.getEncryptionAlgorithm();
	}

	/** {@inheritDoc} */
	public String getHashAlgorithm()
	{
		return wrapped.getHashAlgorithm();
	}

	/** {@inheritDoc} */
	public String getCharacterEncoding()
	{
		return wrapped.getCharacterEncoding();
	}

	/** {@inheritDoc} */
	public String getDigitalSignatureAlgorithm()
	{
		return wrapped.getDigitalSignatureAlgorithm();
	}

	/** {@inheritDoc} */
	public String getRandomAlgorithm()
	{
		return wrapped.getRandomAlgorithm();
	}

	/** {@inheritDoc} */
	public int getAllowedLoginAttempts()
	{
		return wrapped.getAllowedLoginAttempts();
	}

	/** {@inheritDoc} */
	public int getMaxOldPasswordHashes()
	{
		return wrapped.getMaxOldPasswordHashes();
	}

	/** {@inheritDoc} */
	public Threshold getQuota(String eventName)
	{
		return wrapped.getQuota(eventName);
	}

	/** {@inheritDoc} */
	public String getResourceDirectory()
	{
		return wrapped.getResourceDirectory();
	}

	/** {@inheritDoc} */
	public void setResourceDirectory(String dir)
	{
		wrapped.setResourceDirectory(dir);
	}

	/** {@inheritDoc} */
	public String getResponseContentType()
	{
		return wrapped.getResponseContentType();
	}

	/** {@inheritDoc} */
	public long getRememberTokenDuration()
	{
		return wrapped.getRememberTokenDuration();
	}

	/** {@inheritDoc} */
	public int getSessionIdleTimeoutLength()
	{
		return wrapped.getSessionIdleTimeoutLength();
	}

	/** {@inheritDoc} */
	public int getSessionAbsoluteTimeoutLength()
	{
		return wrapped.getSessionAbsoluteTimeoutLength();
	}

	/** {@inheritDoc} */
	public boolean getLogEncodingRequired()
	{
		return wrapped.getLogEncodingRequired();
	}

	/** {@inheritDoc} */
	public boolean getLogDefaultLog4J()
	{
		return wrapped.getLogDefaultLog4J();
	}

	/** {@inheritDoc} */
	public int getLogLevel()
	{
		return wrapped.getLogLevel();
	}

	/** {@inheritDoc} */
	public String getLogFileName()
	{
		return wrapped.getLogFileName();
	}

	/** {@inheritDoc} */
	public int getMaxLogFileSize()
	{
		return wrapped.getMaxLogFileSize();
	}

	/** {@inheritDoc} */
	public boolean getDisableIntrusionDetection()
	{
		return wrapped.getDisableIntrusionDetection();
	}

	/** {@inheritDoc} */
    public List getSafeHTTPFilterIgnoreURLexact()
    {
        return wrapped.getSafeHTTPFilterIgnoreURLexact();
    }

    /** {@inheritDoc} */
    public List getSafeHTTPFilterIgnoreURLregEx()
    {
        return wrapped.getSafeHTTPFilterIgnoreURLregEx();
    }

    /** {@inheritDoc} */
    public List getSafeHTTPFilterIgnoreURLroot()
    {
        return wrapped.getSafeHTTPFilterIgnoreURLroot();
    }
 
    /** {@inheritDoc} */
    public List getSafeHTTPFilterIgnoreContextURLRoot()
    {
        return wrapped.getSafeHTTPFilterIgnoreContextURLRoot();
    }
    
    
}