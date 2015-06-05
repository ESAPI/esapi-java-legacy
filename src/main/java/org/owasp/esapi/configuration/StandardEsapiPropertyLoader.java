package org.owasp.esapi.configuration;

import org.owasp.esapi.errors.ConfigurationException;

/**
 * Loader capable of loading single security configuration property from standard java properties configuration file.
 */
public class StandardEsapiPropertyLoader implements EsapiPropertyLoader, Comparable<EsapiPropertyLoader>  {

    private String filename;

    private int priority;

    public StandardEsapiPropertyLoader(String filename, int priority) {
        this.filename = filename;
        this.priority = priority;
    }

    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        return 0;
    }

    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        return new byte[0];
    }

    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        return null;
    }

    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        return null;
    }

    @Override
    public int priority() {
        return priority;
    }

    @Override
    public int compareTo(EsapiPropertyLoader compared) {
        if (this.priority > compared.priority()) {
            return 1;
        } else if (this.priority < compared.priority()) {
            return -1;
        }
        return 0;
    }
    
    private void init() {
        // TODO caching the contents of file into Properties object
    }
}
