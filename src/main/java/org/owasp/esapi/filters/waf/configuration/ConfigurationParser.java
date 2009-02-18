package org.owasp.esapi.filters.waf.configuration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Level;
import org.owasp.esapi.filters.waf.ConfigurationException;
import org.owasp.esapi.filters.waf.rules.AuthenticatedRule;
import org.owasp.esapi.filters.waf.rules.IPRule;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Elements;
import nu.xom.ParsingException;
import nu.xom.ValidityException;


public class ConfigurationParser {

	private static final String REGEX = "regex";

	public static AppGuardianConfiguration readConfigurationFile(File configFile) throws ConfigurationException {

		AppGuardianConfiguration config = new AppGuardianConfiguration();

		Builder parser = new Builder();
		Document doc;
		Element root;

		try {

			doc = parser.build(configFile);
			root = doc.getRootElement();

			Element aliasesRoot = root.getFirstChildElement("aliases");
			Element settingsRoot = root.getFirstChildElement("settings");
			Element authNRootNode = root.getFirstChildElement("authentication-rules");
			Element authZRootNode = root.getFirstChildElement("authorization-rules");
			Element urlRoot = root.getFirstChildElement("url-rules");
			Element headerRoot = root.getFirstChildElement("header-rules");
			Element customRulesRoot = root.getFirstChildElement("custom-rules");;
			Element virtualPatchesRoot = root.getFirstChildElement("virtual-patches");
			Element outboundRoot = root.getFirstChildElement("outbound-rules");

			/**
			 * Parse the 'aliases' section.
			 */
			Elements aliases = aliasesRoot.getChildElements("alias");

			for(int i=0;i<aliases.size();i++) {
				Element e = aliases.get(i);
				String name = e.getAttributeValue("name");
				String type = e.getAttributeValue("type");
				String value = e.getValue();
				if ( REGEX.equals(type) ) {
					config.addAlias(name, Pattern.compile(value));
				} else {
					config.addAlias(name, value);
				}
			}

			/**
			 * Parse the 'settings' section.
			 */
			String mode = settingsRoot.getFirstChildElement("mode").getValue();

			if ( "block".equals(mode.toLowerCase() ) ) {
				config.setDefaultFailRule(AppGuardianConfiguration.BLOCK);
			} else {
				config.setDefaultFailRule(AppGuardianConfiguration.DONT_BLOCK);
			}

			Element errorHandlingRoot = settingsRoot.getFirstChildElement("error-handling");

			config.setDefaultErrorPage( errorHandlingRoot.getFirstChildElement("default-page").getValue() );
			config.setDefaultResponseCode( Integer.parseInt(errorHandlingRoot.getFirstChildElement("default-status").getValue()) );

			Element loggingRoot = settingsRoot.getFirstChildElement("logging");

			config.setLogDirectory(loggingRoot.getFirstChildElement("log-directory").getValue());
			config.setLogLevel( Level.toLevel(loggingRoot.getFirstChildElement("log-level").getValue()));

			/**
			 * Parse the 'authentication-rules' section if they have one.
			 */
			if ( authNRootNode != null ) {

				String key = authNRootNode.getAttributeValue("key");
				AuthenticatedRule rule = new AuthenticatedRule(key,getExceptionsFromElement(authNRootNode));
				config.addBeforeBodyRule(rule);
			}

			/**
			 * Parse 'authorization-rules' section if they have one.
			 */

			if ( authZRootNode != null ) {

				Elements restrictNodes = authZRootNode.getChildElements("restrict-source-ip");

				for(int i=0;i<restrictNodes.size();i++) {

					Element restrictNodeRoot = restrictNodes.get(i);
					Pattern ips = Pattern.compile(restrictNodeRoot.getAttributeValue("ip-regex"));
					if ( REGEX.equalsIgnoreCase(restrictNodeRoot.getAttributeValue("type")) ) {
						config.addBeforeBodyRule( new IPRule(ips, Pattern.compile(restrictNodeRoot.getValue())));
					} else {
						config.addBeforeBodyRule( new IPRule(ips, restrictNodeRoot.getValue()) );
					}

				}

			}


		} catch (ValidityException e) {
			throw new ConfigurationException(e);
		} catch (ParsingException e) {
			throw new ConfigurationException(e);
		} catch (IOException e) {
			throw new ConfigurationException(e);
		}

		return config;

	}

	private static List<Object> getExceptionsFromElement(Element root) {
		Elements exceptions = root.getChildElements("exception");
		ArrayList<Object> exceptionList = new ArrayList<Object>();

		for(int i=0;i<exceptions.size();i++) {
			Element e = exceptions.get(i);
			if ( REGEX.equalsIgnoreCase(e.getAttributeValue("type"))) {
				exceptionList.add( Pattern.compile(e.getValue()) );
			} else {
				exceptionList.add( e.getValue() );
			}
		}
		return exceptionList;
	}

}
