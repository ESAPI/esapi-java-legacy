/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi.reference.validation;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;
import org.owasp.validator.html.ScanException;


/**
 * A validator performs syntax and possibly semantic validation of a single
 * piece of data from an untrusted source.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class HTMLValidationRule extends StringValidationRule {

	/** OWASP AntiSamy markup verification policy */
	private static Policy antiSamyPolicy = null;
	private static final Logger LOGGER = ESAPI.getLogger( "HTMLValidationRule" );

	static {
        InputStream resourceStream = null;
		try {
			resourceStream = ESAPI.securityConfiguration().getResourceStream("antisamy-esapi.xml");
		} catch (IOException e) {
			throw new ConfigurationException("Couldn't find antisamy-esapi.xml", e);
	            }
        if (resourceStream != null) {
        	try {
				antiSamyPolicy = Policy.getInstance(resourceStream);
			} catch (PolicyException e) {
				throw new ConfigurationException("Couldn't parse antisamy policy", e);
		        }
			}
		}

	public HTMLValidationRule( String typeName ) {
		super( typeName );
	}

	public HTMLValidationRule( String typeName, Encoder encoder ) {
		super( typeName, encoder );
	}

	public HTMLValidationRule( String typeName, Encoder encoder, String whitelistPattern ) {
		super( typeName, encoder, whitelistPattern );
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public String getValid( String context, String input ) throws ValidationException {
		return invokeAntiSamy( context, input );
	}

    /**
     * {@inheritDoc}
     */
	@Override
	public String sanitize( String context, String input ) {
		String safe = "";
		try {
			safe = invokeAntiSamy( context, input );
		} catch( ValidationException e ) {
			// just return safe
		}
		return safe;
	}

    /**
     * Check whether we want the legacy behavior ("clean") or the presumably intended
     * behavior of "throw" for how to treat unsafe HTML input when AntiSamy is invoked.
     * This admittedly is an UGLY hack to ensure that issue 509 and its corresponding
     * fix in PR #510 does not break existing developer's existing code. Full
     * details are described in GitHub issue 521.
     *
     * Checks new ESAPI property "Validator.HtmlValidationAction". A value of "clean"
     * means to revert to legacy behavior. A value of "throw" means to use the new
     * behavior as implemented in GitHub issue 509.
     *
     * @return false - If  "Validator.HtmlValidationAction" is set to "throw". Otherwise {@code true}.
     * @since 2.2.1.0
     */
    private boolean legacyHtmlValidation() {
        boolean legacy = true;          // Make legacy support the default behavior for backward compatibility.
        String propValue = "clean";     // For legacy support.
        try {
            // DISCUSS:
            // Hindsight: maybe we should have getBooleanProp(), getStringProp(),
            // getIntProp() methods that take a default arg as well?
            // At least for ESAPI 3.x.
            propValue = ESAPI.securityConfiguration().getStringProp(
                                // Future: This will be moved to a new PropNames class
                            org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION );
            switch ( propValue.toLowerCase() ) {
                case "throw":
                    legacy = false;     // New, presumably correct behavior, as addressed by GitHub issue 509
                    break;
                case "clean":
                    legacy = true;      // Give the caller that legacy behavior of sanitizing.
                    break;
                default:
                    LOGGER.warning(Logger.EVENT_FAILURE, "ESAPI property " + 
                                   org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION +
                                   " was set to \"" + propValue + "\".  Must be set to either \"clean\"" +
                                   " (the default for legacy support) or \"throw\"; assuming \"clean\" for legacy behavior.");
                    legacy = true;
                    break;
            }
        } catch( ConfigurationException cex ) {
            // OPEN ISSUE: Should we log this? I think so. Convince me otherwise. But maybe
            //             we should only log it once or every Nth time??
            LOGGER.warning(Logger.EVENT_FAILURE, "ESAPI property " + 
                           org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_ACTION +
                           " must be set to either \"clean\" (the default for legacy support) or \"throw\"; assuming \"clean\"",
                           cex);
        }

        return legacy;
    }

	private String invokeAntiSamy( String context, String input ) throws ValidationException {
		// CHECKME should this allow empty Strings? "   " use IsBlank instead?
	    if ( StringUtilities.isEmpty(input) ) {
			if (allowNull) {
				return null;
			}
			throw new ValidationException( context + " is required", "AntiSamy validation error: context=" + context + ", input=" + input, context );
	    }

		String canonical = super.getValid( context, input );

		try {
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(canonical, antiSamyPolicy);

			List<String> errors = test.getErrorMessages();
			if ( !errors.isEmpty() ) {
                if ( legacyHtmlValidation() ) {        // See GitHub issues 509 and 521
                    LOGGER.info(Logger.SECURITY_FAILURE, "Cleaned up invalid HTML input: " + errors );
                } else {
				    throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " errors=" + errors.toString());
                }
			}

			return test.getCleanHTML().trim();

		} catch (ScanException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input: context=" + context + " error=" + e.getMessage(), e, context );
		} catch (PolicyException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " error=" + e.getMessage(), e, context );
		}
	}
}

