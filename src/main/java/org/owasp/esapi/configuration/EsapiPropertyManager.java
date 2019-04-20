package org.owasp.esapi.configuration;

import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.util.TreeSet;

import static org.owasp.esapi.configuration.EsapiPropertyLoaderFactory.createPropertyLoader;

/**
 * Manager used for loading security configuration properties. Does all the logic to obtain the correct property from
 * correct source. Uses following system properties to find configuration files:
 * <pre>
 * - org.owasp.esapi.devteam - lower priority dev file path
 * - org.owasp.esapi.opsteam - higher priority ops file path
 * </pre>
 *
 * @since 2.2
 */
public class EsapiPropertyManager implements EsapiPropertyLoader {

    protected TreeSet<AbstractPrioritizedPropertyLoader> loaders;

    public EsapiPropertyManager() {
        initLoaders();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getIntProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getIntProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.name());
            }
        }
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getByteArrayProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getByteArrayProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.name());
            }
        }
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Boolean getBooleanProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getBooleanProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property not found in " + loader.name());
            }
        }
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getStringProp(String propertyName) throws ConfigurationException {
        for (AbstractPrioritizedPropertyLoader loader : loaders) {
            try {
                return loader.getStringProp(propertyName);
            } catch (ConfigurationException e) {
                System.err.println("Property : " + propertyName + " not found in " + loader.name());
            }
        }
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    private void initLoaders() {
        loaders = new TreeSet<AbstractPrioritizedPropertyLoader>();
        try {
            loaders.add(createPropertyLoader(EsapiConfiguration.OPSTEAM_ESAPI_CFG));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        try {
            loaders.add(createPropertyLoader(EsapiConfiguration.DEVTEAM_ESAPI_CFG));
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }


}
