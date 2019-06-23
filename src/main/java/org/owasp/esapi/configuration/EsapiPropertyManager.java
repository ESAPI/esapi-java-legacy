package org.owasp.esapi.configuration;

import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.util.TreeSet;
import java.io.IOException;

import static org.owasp.esapi.configuration.EsapiPropertyLoaderFactory.createPropertyLoader;

// Have dependency like this on a reference implmentation is majorly ugly, I know, but I
// don't want to refactor code and delay the 2.2.0.0 release further and this class
// is WAY too noisy. - kwwall
import static org.owasp.esapi.reference.DefaultSecurityConfiguration.logToStdout;

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

    public EsapiPropertyManager() throws IOException {
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
                logToStdout("Integer property '" + propertyName + "' not found in " + loader.name(), e);
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
                logToStdout("Byte array property '" + propertyName + "' not found in " + loader.name(), e);
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
                logToStdout("Boolean property '" + propertyName + "' not found in " + loader.name(), e);
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
                logToStdout("Property '" + propertyName + "' not found in " + loader.name(), e);
            }
        }
        throw new ConfigurationException("Could not find property " + propertyName + " in configuration");
    }

    private void initLoaders() throws IOException {
        loaders = new TreeSet<AbstractPrioritizedPropertyLoader>();
        try {
            AbstractPrioritizedPropertyLoader appl = createPropertyLoader(EsapiConfiguration.OPSTEAM_ESAPI_CFG);
            if ( appl == null ) {
                String msg = "WARNING: System property [" + EsapiConfiguration.OPSTEAM_ESAPI_CFG.getConfigName() + "] is not set";
                logToStdout(msg, null);
            } else {
                loaders.add( appl );
            }
        } catch (IOException e) {
            logToStdout("WARNING: Exception encountered while setting up ESAPI configuration manager for OPS team", e);
            throw e;
        }
        try {
            AbstractPrioritizedPropertyLoader appl = createPropertyLoader(EsapiConfiguration.DEVTEAM_ESAPI_CFG);
            if ( appl == null ) {
                String msg = "WARNING: System property [" + EsapiConfiguration.DEVTEAM_ESAPI_CFG.getConfigName() + "] is not set";
                logToStdout(msg, null);
            } else {
                loaders.add( appl );
            }
        } catch (IOException e) {
            logToStdout("WARNING: Exception encountered while setting up ESAPI configuration manager for DEV team", e);
            throw e;
        }
    }
}
