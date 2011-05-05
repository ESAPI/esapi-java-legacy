package org.owasp.esapi.reference;

import java.util.Properties;

public class UnitTestSecurityConfiguration extends DefaultSecurityConfiguration {
    public UnitTestSecurityConfiguration(DefaultSecurityConfiguration cfg) {
        super(cfg.getESAPIProperties());
    }

    /**
	 * {@inheritDoc}
	 */
    public void setApplicationName(String v) {
    	getESAPIProperties().setProperty(APPLICATION_NAME, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setLogImplementation(String v) {
    	getESAPIProperties().setProperty(LOG_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setAuthenticationImplementation(String v) {
    	getESAPIProperties().setProperty(AUTHENTICATION_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setEncoderImplementation(String v) {
    	getESAPIProperties().setProperty(ENCODER_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setAccessControlImplementation(String v) {
    	getESAPIProperties().setProperty(ACCESS_CONTROL_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setEncryptionImplementation(String v) {
    	getESAPIProperties().setProperty(ENCRYPTION_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setIntrusionDetectionImplementation(String v) {
    	getESAPIProperties().setProperty(INTRUSION_DETECTION_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setRandomizerImplementation(String v) {
    	getESAPIProperties().setProperty(RANDOMIZER_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setExecutorImplementation(String v) {
    	getESAPIProperties().setProperty(EXECUTOR_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setHTTPUtilitiesImplementation(String v) {
    	getESAPIProperties().setProperty(HTTP_UTILITIES_IMPLEMENTATION, v);
    }

    /**
	 * {@inheritDoc}
	 */
    public void setValidationImplementation(String v) {
    	getESAPIProperties().setProperty(VALIDATOR_IMPLEMENTATION, v);
    }

}
