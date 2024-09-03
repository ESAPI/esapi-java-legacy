package org.owasp.esapi.configuration;

import org.owasp.esapi.errors.ConfigurationException;

/**
 * Generic interface for loading security configuration properties.
 *
 * @since 2.2
 */
public interface EsapiPropertyLoader {

    /**
     * Get any int type property from security configuration.
     *
     * @return property value.
     * @throws ConfigurationException when property does not exist in configuration or has incorrect type.
     */
    public int getIntProp(String propertyName) throws ConfigurationException;

    /**
     * Get any byte array type property from security configuration.
     *
     * @return property value.
     * @throws ConfigurationException when property does not exist in configuration or has incorrect type.
     */
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException;

    /**
     * Get any Boolean type property from security configuration.
     *
     * @return property value.
     * @throws ConfigurationException when property does not exist in configuration or has incorrect type.
     */
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException;

    /**
     * Get any property from security configuration. As every property can be returned as string, this method
     * throws exception only when property does not exist.
     *
     * @return property value.
     * @throws ConfigurationException when property does not exist in configuration.
     */
    public String getStringProp(String propertyName) throws ConfigurationException;

}
