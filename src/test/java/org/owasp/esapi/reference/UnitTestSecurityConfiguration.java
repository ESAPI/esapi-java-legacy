package org.owasp.esapi.reference;

public class UnitTestSecurityConfiguration extends DefaultSecurityConfiguration {
    public UnitTestSecurityConfiguration(DefaultSecurityConfiguration cfg) {
        super(cfg.getESAPIProperties());
    }

    public void setApplicationName(String v) {
    	getESAPIProperties().setProperty(APPLICATION_NAME, v);
    }

    public void setLogImplementation(String v) {
    	getESAPIProperties().setProperty(LOG_IMPLEMENTATION, v);
    }

    public void setAuthenticationImplementation(String v) {
    	getESAPIProperties().setProperty(AUTHENTICATION_IMPLEMENTATION, v);
    }

    public void setEncoderImplementation(String v) {
    	getESAPIProperties().setProperty(ENCODER_IMPLEMENTATION, v);
    }

    public void setAccessControlImplementation(String v) {
    	getESAPIProperties().setProperty(ACCESS_CONTROL_IMPLEMENTATION, v);
    }

    public void setEncryptionImplementation(String v) {
    	getESAPIProperties().setProperty(ENCRYPTION_IMPLEMENTATION, v);
    }

    public void setIntrusionDetectionImplementation(String v) {
    	getESAPIProperties().setProperty(INTRUSION_DETECTION_IMPLEMENTATION, v);
    }

    public void setRandomizerImplementation(String v) {
    	getESAPIProperties().setProperty(RANDOMIZER_IMPLEMENTATION, v);
    }

    public void setExecutorImplementation(String v) {
    	getESAPIProperties().setProperty(EXECUTOR_IMPLEMENTATION, v);
    }

    public void setHTTPUtilitiesImplementation(String v) {
    	getESAPIProperties().setProperty(HTTP_UTILITIES_IMPLEMENTATION, v);
    }

    public void setValidationImplementation(String v) {
    	getESAPIProperties().setProperty(VALIDATOR_IMPLEMENTATION, v);
    }

}
