package org.owasp.esapi.contrib.spring.encryptedproperty;

import org.owasp.esapi.EncryptedProperties;
import org.owasp.esapi.reference.crypto.ReferenceEncryptedProperties;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;
import org.springframework.util.CollectionUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

public class EncryptedPropertyPlaceholderConfigurer extends PropertyPlaceholderConfigurer {

	private EncryptedProperties[] localProperties;

	private boolean localOverride = false;

	/**
	 * Set whether local properties override properties from files.
	 * <p>Default is "false": Properties from files override local defaults.
	 * Can be switched to "true" to let local properties override defaults
	 * from files.
	 */
	@Override
	public void setLocalOverride(boolean localOverride) {
		this.localOverride = localOverride;
		super.setLocalOverride(localOverride);
	}

     /**
      * Set local properties, e.g. via the "props" tag in XML bean definitions.
      * These can be considered defaults, to be overridden by properties
      * loaded from files.
      */
	@Override
     public void setProperties(Properties properties) {

		 if (properties instanceof EncryptedProperties) {
			 //we have an EncryptedProperties already. Set it into the superclass
	         super.setPropertiesArray(new Properties[] {(Properties)properties});
		 } else {
			//create an EncryptedProperties
		    EncryptedProperties eProps = new ReferenceEncryptedProperties(properties);

			super.setPropertiesArray(new Properties[] {(Properties)eProps});
		 }
     }

     /**
      * Set local properties, e.g. via the "props" tag in XML bean definitions,
      * allowing for merging multiple properties sets into one.
      */
	@Override
     public void setPropertiesArray(Properties[] propertiesArray) {

		 ArrayList<Properties> propsList = new ArrayList<Properties>(propertiesArray.length);

		 for (Properties properties : propertiesArray) {
			 if (properties instanceof EncryptedProperties) {
				//we have an EncryptedProperties already. Set it into the array
				propsList.add(properties);
			 } else {
				//create an EncryptedProperties
			    ReferenceEncryptedProperties eProps = new ReferenceEncryptedProperties(properties);
				propsList.add(eProps);
			}
		 }

		super.setPropertiesArray(propsList.toArray(new Properties[propsList.size()]));
     }

	/**
	 * Return a merged Properties instance containing both the
	 * loaded properties and properties set on this FactoryBean.
	 */
	@Override
	protected Properties mergeProperties() throws IOException {
		ReferenceEncryptedProperties result = new ReferenceEncryptedProperties();

		if (this.localOverride) {
			// Load properties from file upfront, to let local properties override.
			loadProperties(result);
		}

		if (this.localProperties != null) {
			for (int i = 0; i < this.localProperties.length; i++) {
				CollectionUtils.mergePropertiesIntoMap((Properties) this.localProperties[i], result);
			}
		}

		if (!this.localOverride) {
			// Load properties from file afterwards, to let those properties override.
			loadProperties(result);
		}

		return result;
	}

	/**
	 * Load properties into the given instance.
	 * @param props the Properties instance to load into
	 * @throws java.io.IOException in case of I/O errors
	 * @see #setLocations
	 */
	@Override
	protected void loadProperties(Properties props) throws IOException {

		if (!(props instanceof EncryptedProperties)) props = new ReferenceEncryptedProperties(props);

		super.loadProperties(props);
	}
}