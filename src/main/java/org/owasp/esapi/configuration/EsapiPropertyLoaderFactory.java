package org.owasp.esapi.configuration;

import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.FileNotFoundException;

import static org.owasp.esapi.configuration.consts.EsapiConfigurationType.PROPERTIES;
import static org.owasp.esapi.configuration.consts.EsapiConfigurationType.XML;

/**
 * Factory class that takes care of initialization of proper instance of EsapiPropertyLoader
 * based on EsapiPropertiesStore
 *
 * @since 2.2
 */
public class EsapiPropertyLoaderFactory {

    public static AbstractPrioritizedPropertyLoader createPropertyLoader(EsapiConfiguration cfg)
            throws ConfigurationException, FileNotFoundException {
        String cfgPath = System.getProperty(cfg.getConfigName());
        if (cfgPath == null) {
            throw new ConfigurationException("System property [" + cfg.getConfigName() + "] is not set");
        }
        String fileExtension = cfgPath.substring(cfgPath.lastIndexOf('.') + 1);

        if (XML.getTypeName().equals(fileExtension)) {
            return new XmlEsapiPropertyLoader(cfgPath, cfg.getPriority());
        }
        if (PROPERTIES.getTypeName().equals(fileExtension)) {
            return new StandardEsapiPropertyLoader(cfgPath, cfg.getPriority());
        } else {
            throw new ConfigurationException("Configuration storage type [" + fileExtension + "] is not " +
                    "supported");
        }
    }
    
}
