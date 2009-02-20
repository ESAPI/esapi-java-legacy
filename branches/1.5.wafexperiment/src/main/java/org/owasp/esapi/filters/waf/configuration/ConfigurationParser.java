package org.owasp.esapi.filters.waf.configuration;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.log4j.Level;
import org.owasp.esapi.filters.waf.ConfigurationException;
import org.owasp.esapi.filters.waf.rules.AuthenticatedRule;
import org.owasp.esapi.filters.waf.rules.EnforceHTTPSRule;
import org.owasp.esapi.filters.waf.rules.HTTPMethodRule;
import org.owasp.esapi.filters.waf.rules.IPRule;
import org.owasp.esapi.filters.waf.rules.MustMatchRule;
import org.owasp.esapi.filters.waf.rules.PathExtensionRule;
import org.owasp.esapi.filters.waf.rules.RestrictContentTypeRule;
import org.owasp.esapi.filters.waf.rules.RestrictUserAgentRule;
import org.owasp.esapi.filters.waf.rules.SimpleVirtualPatchRule;

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
			Element authNRoot = root.getFirstChildElement("authentication-rules");
			Element authZRoot = root.getFirstChildElement("authorization-rules");
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
			if ( authNRoot != null ) {

				String key = authNRoot.getAttributeValue("key");
				AuthenticatedRule rule = new AuthenticatedRule(key,getExceptionsFromElement(authNRoot));
				config.addBeforeBodyRule(rule);
			}

			/**
			 * Parse 'authorization-rules' section if they have one.
			 */

			if ( authZRoot != null ) {

				Elements restrictNodes = authZRoot.getChildElements("restrict-source-ip");

				for(int i=0;i<restrictNodes.size();i++) {

					Element restrictNodeRoot = restrictNodes.get(i);
					Pattern ips = Pattern.compile(restrictNodeRoot.getAttributeValue("ip-regex"));
					if ( REGEX.equalsIgnoreCase(restrictNodeRoot.getAttributeValue("type")) ) {
						config.addBeforeBodyRule( new IPRule(ips, Pattern.compile(restrictNodeRoot.getValue())));
					} else {
						config.addBeforeBodyRule( new IPRule(ips, restrictNodeRoot.getValue()) );
					}

				}

				Elements mustMatchNodes = authZRoot.getChildElements("must-match");

				for(int i=0;i<mustMatchNodes.size();i++) {

					Element e = mustMatchNodes.get(i);
					Pattern path = Pattern.compile(e.getAttributeValue("path"));
					String variable = e.getAttributeValue("variable");
					String value = e.getAttributeValue("value");
					String operator = e.getAttributeValue("operator");
					int op = AppGuardianConfiguration.OPERATOR_EQ;

					if ( "exists".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_EXISTS;
					} else if ( "inList".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_IN_LIST;
					} else if ( "contains".equalsIgnoreCase(operator)) {
						op = AppGuardianConfiguration.OPERATOR_CONTAINS;
					}

					config.addBeforeBodyRule( new MustMatchRule(path,variable,op,value) );
				}

			}

			/**
			 * Parse the 'url-rules' section if they have one.
			 */
			if ( urlRoot != null ) {

				Elements restrictExtensionNodes = urlRoot.getChildElements("restrict-extension");
				Elements restrictMethodNodes = urlRoot.getChildElements("restrict-method");
				Elements enforceHttpsNodes = urlRoot.getChildElements("enforce-https");

				/*
				 * Read in rules that allow an app to restrict by extension.
				 * E.g., you may want to explicitly only allow:
				 *  .jsp, .jpg, .gif, .css, .js, etc.
				 *
				 * You may also want to instead explicitly deny:
				 * .bak, .log, .txt, etc.
				 */

				for (int i=0;i<restrictExtensionNodes.size();i++) {
					Element e = restrictExtensionNodes.get(i);
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");

					if ( allow != null && deny != null ) {
						throw new ConfigurationException( "restrict-extension rules can't have both 'allow' and 'deny'" );
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new PathExtensionRule(Pattern.compile(allow),null) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new PathExtensionRule(null,Pattern.compile(deny)) );

					} else {
						throw new ConfigurationException("restrict extension rule should have either a 'deny' or 'allow' attribute");
					}
				}

				/*
				 * Read in rules that allow the site to control
				 * which HTTP methods are allowed to reach the
				 * app.
				 *
				 * 99% of the time, you'll only need POST and
				 * GET.
				 */
				for (int i=0;i<restrictMethodNodes.size();i++) {

					Element e = restrictMethodNodes.get(i);

					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					String path = e.getAttributeValue("path");

					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-method rule should not have both 'allow' and 'deny' values");
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new HTTPMethodRule(Pattern.compile(allow), null, Pattern.compile(path)) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new HTTPMethodRule(null, Pattern.compile(deny), Pattern.compile(path)) );

					} else {
						throw new ConfigurationException("restrict-method rule should have either an 'allow' or 'deny' value");
					}
				}

				for (int i=0;i<enforceHttpsNodes.size();i++) {

					Element e = (Element)enforceHttpsNodes.get(i);
					String path = e.getAttributeValue("path");
					List<Object> exceptions = getExceptionsFromElement(e);

					config.addBeforeBodyRule( new EnforceHTTPSRule(Pattern.compile(path),exceptions) );
				}

			}

			if ( headerRoot != null ) {
				Elements restrictContentTypes = headerRoot.getChildElements("restrict-content-type");
				Elements restrictUserAgents = headerRoot.getChildElements("restrict-user-agent");

				for(int i=0;i<restrictContentTypes.size();i++) {
					Element e = restrictContentTypes.get(i);
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-content-type rule should not have both 'allow' and 'deny' values");
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new RestrictContentTypeRule(Pattern.compile(allow), null) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new RestrictContentTypeRule(null, Pattern.compile(deny)) );

					} else {
						throw new ConfigurationException("restrict-content-type rule should have either an 'allow' or 'deny' value");
					}
				}

				for(int i=0;i<restrictUserAgents.size();i++) {
					Element e = restrictUserAgents.get(i);
					String allow = e.getAttributeValue("allow");
					String deny = e.getAttributeValue("deny");
					if ( allow != null && deny != null ) {
						throw new ConfigurationException("restrict-user-agent rule should not have both 'allow' and 'deny' values");
					}

					if ( allow != null ) {

						config.addBeforeBodyRule( new RestrictUserAgentRule(Pattern.compile(allow), null) );

					} else if ( deny != null ) {

						config.addBeforeBodyRule( new RestrictUserAgentRule(null, Pattern.compile(deny)) );

					} else {
						throw new ConfigurationException("restrict-user-agent rule should have either an 'allow' or 'deny' value");
					}
				}

			}

			if ( virtualPatchesRoot != null ) {
				Elements virtualPatchNodes = virtualPatchesRoot.getChildElements("virtual-patch");
				for(int i=0;i<virtualPatchNodes.size();i++) {
					Element e = virtualPatchNodes.get(i);
					String id = e.getAttributeValue("id");
					String path = e.getAttributeValue("path");
					String variable = e.getAttributeValue("variable");
					String pattern = e.getAttributeValue("pattern");
					String message = e.getAttributeValue("message");

					config.addAfterBodyRule( new SimpleVirtualPatchRule(id, Pattern.compile(path), variable, Pattern.compile(pattern), message) );
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
