package org.owasp.esapi.filters.waf.rules;

import java.io.File;

import org.owasp.esapi.filters.waf.AppGuardianConfiguration;

public class ConfigurationParser {

	public static AppGuardianConfiguration readConfigurationFile(File configFile) {
		return new AppGuardianConfiguration();
	}

}
