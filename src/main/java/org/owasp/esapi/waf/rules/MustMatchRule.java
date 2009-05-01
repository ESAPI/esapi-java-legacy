package org.owasp.esapi.waf.rules;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.waf.actions.Action;
import org.owasp.esapi.waf.actions.DefaultAction;
import org.owasp.esapi.waf.actions.DoNothingAction;
import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletRequest;
import org.owasp.esapi.waf.internal.InterceptingHTTPServletResponse;

public class MustMatchRule extends Rule {

	private static final String REQUEST_PARAMETERS = "request.parameters.";
	private static final String REQUEST_HEADERS = "request.headers.";
	private static final String REQUEST_URI = "request.uri";
	private static final String REQUEST_URL = "request.url";
	private static final String SESSION_ATTRIBUTES = "session.";

	private Pattern path;
	private String variable;
	private int operator;
	private String value;

	public MustMatchRule(String id, Pattern path, String variable, int operator, String value) {
		this.path = path;
		this.variable = variable;
		this.operator = operator;
		this.value = value;
		setId(id);
	}

	public Action check(HttpServletRequest req,
			InterceptingHTTPServletResponse response) {

		InterceptingHTTPServletRequest request = (InterceptingHTTPServletRequest)req;

		String uri = request.getRequestURI();
		if ( ! path.matcher(uri).matches() ) {

			return new DoNothingAction();

		} else {

			String target = null;

			/*
			 * First check if we're going to be dealing with request parameters
			 */
			if ( variable.startsWith( REQUEST_PARAMETERS ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS ) {

					target = variable.substring(REQUEST_PARAMETERS.length());

					if ( request.getParameter(target) != null ) {
						return new DoNothingAction();
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
					target = variable.substring(REQUEST_PARAMETERS.length());

					if ( target.contains("*") || target.contains("?") ) {

						target = target.replaceAll("*", ".*");
						Pattern p = Pattern.compile(target);

						Enumeration e = request.getParameterNames();

						while(e.hasMoreElements()) {
							String param = (String)e.nextElement();

							if ( p.matcher(param).matches() ) {
								String s = request.getParameter(param);
								if ( ! RuleUtil.testValue(s, value, operator) ) {
									log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', input='" + s + "' parameter='"+param+"'");
									return new DefaultAction();
								}
							}
						}

					} else {

						String s = request.getParameter(target);

						if ( ! RuleUtil.testValue(s, value, operator) ) {
							log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', input='" + s + "', parameter='"+target+"'");
							return new DefaultAction();
						}

					}
				}

			} else if ( variable.startsWith( REQUEST_HEADERS ) ) {

				/**
				 * Do the same for request headers.
				 */

				if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS ) {

					target = variable.substring(REQUEST_HEADERS.length());

					if ( request.getHeader(target) != null ) {
						return new DoNothingAction();
					}

				} else if ( operator == AppGuardianConfiguration.OPERATOR_IN_LIST ) {

					/*
					 * This doesn't make sense. The variable to test is a request header
					 * but the rule is looking for a List. Let the control fall through
					 * to the bottom where we'll return false.
					 */

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {

					target = variable.substring(REQUEST_HEADERS.length());

					if ( target.contains("*") || target.contains("?") ) {

						target = target.replaceAll("*", ".*");
						Pattern p = Pattern.compile(target);

						Enumeration e = request.getHeaderNames();

						while(e.hasMoreElements()) {
							String header = (String)e.nextElement();
							if ( p.matcher(header).matches() ) {
								String s = request.getHeader(header);
								if ( ! RuleUtil.testValue(s, value, operator) ) {
									log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', input='" + s + "', header='"+header+"'");
									return new DefaultAction();
								}
							}
						}

						return new DoNothingAction();

					} else {

						String s = request.getHeader(target);

						if ( s == null || ! RuleUtil.testValue(s, value, operator) ) {
							log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', input='" + s + "', header='"+target+"'");
							return new DefaultAction();
						}

						return new DoNothingAction();

					}

				}

			} else if ( variable.startsWith(SESSION_ATTRIBUTES) ) {

				/**
				 * Do the same for session attributes. Can't possibly match
				 * ANY rule if there is no session object.
				 */
				if ( request.getSession(false) == null ) {
					return new DefaultAction();
				}

				target = variable.substring(SESSION_ATTRIBUTES.length()+1);

				if ( operator == AppGuardianConfiguration.OPERATOR_IN_LIST ) {

					/*
					 * Want to check if the List/Enumeration/whatever stored
					 * in "target" contains the value in "value".
					 */

					Object o = request.getSession(false).getAttribute(target);

					if ( o instanceof Collection ) {
						if ( RuleUtil.isInList((Collection)o, value) ) {
							return new DoNothingAction();
						} else {
							log(request, "MustMatch rule failed - looking for value='" + value + "', in session Collection attribute '" + target + "']");
							return new DefaultAction();
						}
					} else if ( o instanceof Map ) {
						if ( RuleUtil.isInList((Map)o, value) ) {
							return new DoNothingAction();
						} else {
							log(request, "MustMatch rule failed - looking for value='" + value + "', in session Map attribute '" + target + "']");
							return new DefaultAction();
						}
					} else if ( o instanceof Enumeration ) {
						if ( RuleUtil.isInList((Enumeration)o, value) ) {
							return new DoNothingAction();
						} else {
							log(request, "MustMatch rule failed - looking for value='" + value + "', in session Enumeration attribute '" + target + "']");
							return new DefaultAction();
						}
					}

					/*
					 * The attribute was not a common list-type of Java object s
					 * let the control fall through to the bottom where it will
					 * fail.
					 */

				} else if ( operator == AppGuardianConfiguration.OPERATOR_EXISTS) {

					Object o = request.getSession(false).getAttribute(target);

					if ( o != null ) {
						return new DoNothingAction();
					} else {
						log(request, "MustMatch rule failed - couldn't find required session attribute='" + target + "'");
						return new DefaultAction();
					}

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
									log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', session attribute='" + attr + "', attribute value='"+(String)o+"'");
									return new DefaultAction();
								} else {
									return new DoNothingAction();
								}
							}
						}

					} else {

						Object o = request.getSession(false).getAttribute(target);

						if ( ! RuleUtil.testValue((String)o, value, operator) ) {
							log(request, "MustMatch rule failed (operator="+operator+"), value='" + value + "', session attribute='" + target + "', attribute value='"+(String)o+"'");
							return new DefaultAction();
						} else {
							return new DoNothingAction();
						}

					}

				}

			} else if ( variable.equals( REQUEST_URI ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {
					if ( RuleUtil.testValue(request.getRequestURI(), value, operator) ) {
						return new DoNothingAction();
					} else {
						log(request, "MustMatch rule on request URI failed (operator="+operator+"), requestURI='" + request.getRequestURI() + "', value='" + value+ "'");
						return new DefaultAction();
					}
				}

				/*
				 * Any other operator doesn't make sense.
				 */

			} else if ( variable.equals( REQUEST_URL ) ) {

				if ( operator == AppGuardianConfiguration.OPERATOR_EQ || operator == AppGuardianConfiguration.OPERATOR_CONTAINS ) {
					if ( RuleUtil.testValue(request.getRequestURL().toString(), value, operator) ) {
						return new DoNothingAction();
					} else {
						log(request, "MustMatch rule on request URL failed (operator="+operator+"), requestURL='" + request.getRequestURL() + "', value='" + value+ "'");
						return new DefaultAction();
					}
				}

				/*
				 * Any other operator doesn't make sense.
				 */
			}

		}

		log(request, "MustMatch rule failed close on URL '" + request.getRequestURL() + "'");
		return new DefaultAction();

	}

}
