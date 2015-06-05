package org.owasp.esapi.configuration;

import org.owasp.esapi.errors.ConfigurationException;
/**
 * Generic interface for loading security configuration properties.
 */
public interface EsapiPropertyLoader {

    /**
     * Get any int type property from security configuration.
     *
     * @throws org.owasp.esapi.errors.ConfigurationException when property does not exist or has incorrect type.
     * @return property value.
     */
    public int getIntProp(String propertyName) throws ConfigurationException;

    /**
     * Get any byte array type property from security configuration.
     *
     * @throws  ConfigurationException when property does not exist or has incorrect type.
     * @return property value.
     */
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException;

    /**
     * Get any Boolean type property from security configuration.
     *
     * @throws  ConfigurationException when property does not exist or has incorrect type.
     * @return property value.
     */
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException;

    /**
     * Get any property from security configuration. As every property can be returned as string, this method
     * throws exception only when property does not exist.
     *
     * @throws  ConfigurationException when property does not exist.
     * @return property value.
     */
    public String getStringProp(String propertyName) throws ConfigurationException;

    /**
     * Get priority of this property loader. If two and more loaders can return value for the same property key,
     * the one with highest priority will be chosen.
     * @return priority of this property loader
     */
    public int priority();
}
