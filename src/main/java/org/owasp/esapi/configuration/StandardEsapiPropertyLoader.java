package org.owasp.esapi.configuration;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.*;

/**
 * Loader capable of loading single security configuration property from standard java properties configuration file.
 *
 * @since 2.2
 */
public class StandardEsapiPropertyLoader extends AbstractPrioritizedPropertyLoader {

    public StandardEsapiPropertyLoader(String filename, int priority) {
        super(filename, priority);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + "not found in configuration");
        }
        try {
            return Integer.parseInt(property);
        } catch (NumberFormatException e) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to integer", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        try {
            return ESAPI.encoder().decodeFromBase64(property);
        } catch (IOException e) {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to byte array", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        if (property.equalsIgnoreCase("true") || property.equalsIgnoreCase("yes")) {
            return true;
        }
        if (property.equalsIgnoreCase("false") || property.equalsIgnoreCase("no")) {
            return false;
        } else {
            throw new ConfigurationException("Incorrect type of : " + propertyName + ". Value " + property +
                    "cannot be converted to boolean");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            throw new ConfigurationException("Property : " + propertyName + "not found in default configuration");
        }
        return property;
    }

    /**
     * Methods loads configuration from .properties file. 
     * @param file
     */
    protected void loadPropertiesFromFile(File file) {
        InputStream input = null;
        try {
            input = new FileInputStream(file);
            properties.load(input);
        } catch (IOException ex) {
            logSpecial("Loading " + file.getName() + " via file I/O failed.", ex);
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    logSpecial("Could not close stream");
                }
            }
        }
    }

}
