package org.owasp.esapi.configuration;

import org.owasp.esapi.configuration.consts.EsapiConfiguration;
import org.owasp.esapi.errors.ConfigurationException;

import java.io.IOException;

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
            throws ConfigurationException, IOException {
        String cfgPath = System.getProperty(cfg.getConfigName());
        if ( cfgPath == null || cfgPath.equals("") ) {
            // TODO / FIXME:
            // This case was previously a warning, but it should NOT have been
            // since these system properties are optional. Most people just use
            // the traditional ESAPI.properties file and not these prioritized ones.
            // A warning gets logged in EsapiPropertyManager if logSpecial output
            // has not been discarded.
            //
            // Note also there were a LOT of cases in our JUnit tests where the
            // file extension was empty, causing the ConfigurationException to
            // be thrown with the error message:
            //      "Configuration storage type [] is not supported"
            // I don't think that was intentional, but because prior to the
            // changes for this commit, these were all ConfigurationExceptions
            // and they all were just being caught and not re-thrown by
            // DefaultSecurityConfigurator. I think that is an error, probably
            // in the tests, but I don't have timed to chase it down right now
            // because of the pending 2.2.0.0 release.
            //
            // Also, I made several fixes in DefaultSecurityConfiguration
            // related to this clean-up where IOExceptions were being silently
            // caught when they should not have been.  -kwwall
            return null;
        }
        String fileExtension = cfgPath.substring(cfgPath.lastIndexOf('.') + 1);

        if (XML.getTypeName().equalsIgnoreCase(fileExtension)) {
            return new XmlEsapiPropertyLoader(cfgPath, cfg.getPriority());
        }
        if (PROPERTIES.getTypeName().equalsIgnoreCase(fileExtension)) {
            return new StandardEsapiPropertyLoader(cfgPath, cfg.getPriority());
        } else {
            throw new ConfigurationException("Configuration storage type [" + fileExtension + "] is not " +
                    "supported");
        }
    }
    
}
