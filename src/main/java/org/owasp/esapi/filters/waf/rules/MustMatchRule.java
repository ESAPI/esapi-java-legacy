package org.owasp.esapi.filters.waf.rules;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.regex.Pattern;

import org.owasp.esapi.filters.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.filters.waf.internal.InterceptingHTTPServletResponse;

public class MustMatchRule extends Rule {

	private static final String REQUEST_PARAMETERS = "request.parameters.";
	private static final String REQUEST_HEADERS = "request.headers.";
	private static final String SESSION_ATTRIBUTES = "session.";

	private Pattern path;
	private String variable;
	private int operator;
	private String value;

	public MustMatchRule(Pattern path, String variable, int operator, String value) {
		this.path = path;
		this.variable = variable;
		this.operator = operator;
		this.value = value;
	}

	public boolean check(InterceptingHTTPServletRequest request,
			InterceptingHTTPServletResponse response) {

		if ( path.matcher(request.getRequestURI()).matches() ) {

			String target = null;

			/*
			 * First check if we're going to be dealing with request parameters
			 */
			if ( variable.startsWith( REQUEST_PARAMETERS ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS ) {

					target = variable.substring(REQUEST_PARAMETERS.length()+1);

					if ( request.getParameter(target) != null ) {
						return true;
					}

				} else if ( operator == AppGuardianConfiguration.OPERATOR_IN_LIST ) {

					/*
					 * This doesn't make sense. The variable to test is a request parameter
					 * but the rule is looking for a List. Let the control fall through
					 * to the bottom where we'll return false.
					 */

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {

					/**
					 * Working with request parameters. If we detect
					 * simple regex characters, we treat it as a regex.
					 * Otherwise we treat it as a single parameter.
					 */
					target = variable.substring(REQUEST_PARAMETERS.length()+1);

					if ( target.contains("*") || target.contains("?") ) {

						target = target.replaceAll("*", ".*");
						Pattern p = Pattern.compile(target);

						Enumeration e = request.getParameterNames();

						while(e.hasMoreElements()) {
							String param = (String)e.nextElement();

							if ( p.matcher(param).matches() ) {
								String s = request.getParameter(param);
								if ( ! RuleUtil.testValue(s, value, operator) ) {
									return false;
								}
							}
						}

					} else {

						String s = request.getParameter(target);

						if ( ! RuleUtil.testValue(s, value, operator) ) {
							return false;
						}

					}
				}

			} else if ( variable.startsWith( REQUEST_HEADERS ) ) {

				/**
				 * Do the same for request headers.
				 */

				if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS ) {

					target = variable.substring(REQUEST_HEADERS.length()+1);

					if ( request.getHeader(target) != null ) {
						return true;
					}

				} else if ( operator == AppGuardianConfiguration.OPERATOR_IN_LIST ) {

					/*
					 * This doesn't make sense. The variable to test is a request header
					 * but the rule is looking for a List. Let the control fall through
					 * to the bottom where we'll return false.
					 */

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {

					target = variable.substring(REQUEST_HEADERS.length()+1);

					if ( target.contains("*") || target.contains("?") ) {

						target = target.replaceAll("*", ".*");
						Pattern p = Pattern.compile(target);

						Enumeration e = request.getHeaderNames();

						while(e.hasMoreElements()) {
							String header = (String)e.nextElement();
							if ( p.matcher(header).matches() ) {
								String s = request.getHeader(header);
								if ( ! RuleUtil.testValue(s, value, operator) ) {
									return false;
								}
							}
						}

					} else {

						String s = request.getHeader(target);

						if ( ! RuleUtil.testValue(s, value, operator) ) {
							return false;
						}

					}

				}

			} else if ( variable.startsWith(SESSION_ATTRIBUTES) ) {

				/**
				 * Do the same for session attributes. Can't possibly match
				 * ANY rule if there is no session object.
				 */
				if ( request.getSession(false) == null ) {
					return false;
				}

				target = variable.substring(SESSION_ATTRIBUTES.length()+1);

				if ( operator == AppGuardianConfiguration.OPERATOR_IN_LIST ) {

					/*
					 * Want to check if the List/Enumeration/whatever stored
					 * in "target" contains the value in "value".
					 */

					Object o = request.getSession(false).getAttribute(target);

					if ( o instanceof Collection ) {
						return RuleUtil.isInList((Collection)o, value);
					} else if ( o instanceof Map ) {
						return RuleUtil.isInList((Map)o, value);
					} else if ( o instanceof Enumeration ) {
						return RuleUtil.isInList((Enumeration)o, value);
					}

					/*
					 * The attribute was not a common list-type of Java object s
					 * let the control fall through to the bottom where it will
					 * fail.
					 */

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS) {

					Object o = request.getSession(false).getAttribute(target);

					return o != null;

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {

					if ( target.contains("*") || target.contains("?") ) {

						target = target.replaceAll("*", ".*");
						Pattern p = Pattern.compile(target);

						Enumeration e = request.getSession(false).getAttributeNames();

						while(e.hasMoreElements()) {

							String attr = (String)e.nextElement();

							if (p.matcher(attr).matches() ) {

								Object o = request.getSession(false).getAttribute(attr);

								if ( ! RuleUtil.testValue((String)o, value, operator) ) {
									return false;
								}
							}
						}

					} else {

						Object o = request.getSession(false).getAttribute(target);

						if ( ! RuleUtil.testValue((String)o, value, operator) ) {
							return false;
						}

					}

				}

			} else if ( variable.equals( "request.uri" ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {
					return RuleUtil.testValue(request.getRequestURI(), value, operator);
				}

				/*
				 * Any other operator doesn't make sense.
				 */

			} else if ( variable.equals( "request.url" ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {
					return RuleUtil.testValue(request.getRequestURL().toString(), value, operator);
				}

				/*
				 * Any other operator doesn't make sense.
				 */
			}

		}

		return false;

	}

}
