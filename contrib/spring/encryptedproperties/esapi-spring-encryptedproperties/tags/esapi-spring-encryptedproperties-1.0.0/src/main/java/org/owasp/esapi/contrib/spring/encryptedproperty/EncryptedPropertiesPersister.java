package org.owasp.esapi.contrib.spring.encryptedproperty;

import org.owasp.esapi.EncryptedProperties;
import org.owasp.esapi.reference.crypto.ReferenceEncryptedProperties;
import org.springframework.util.PropertiesPersister;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Properties;

public class EncryptedPropertiesPersister extends org.springframework.util.DefaultPropertiesPersister implements PropertiesPersister {

    @Override
	public void load(Properties props, InputStream is) throws IOException {
		if (!(props instanceof EncryptedProperties)) props = new ReferenceEncryptedProperties(props);

		super.load(props, is);
	}

    @Override
	public void load(Properties props, Reader reader) throws IOException {
		if (!(props instanceof EncryptedProperties)) props = new ReferenceEncryptedProperties(props);

		super.load(props, reader);
	}

    @Override
	public void loadFromXml(Properties props, InputStream is) throws IOException {
		if (!(props instanceof EncryptedProperties)) props = new ReferenceEncryptedProperties(props);

		super.loadFromXml(props, is);
	}
}