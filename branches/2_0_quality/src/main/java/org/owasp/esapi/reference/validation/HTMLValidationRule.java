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

import java.io.InputStream;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
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
	private static Logger logger = ESAPI.getLogger( "HTMLValidationRule" ); 
	
	static {
		try {
			if ( antiSamyPolicy == null ) {
		        InputStream in = null;
	            in = ESAPI.securityConfiguration().getResourceStream("antisamy-esapi.xml");
	            if (in != null) {
	            	antiSamyPolicy = Policy.getInstance(in);
	            }
		        if (antiSamyPolicy == null) {
		            throw new IllegalArgumentException ("Can't find antisamy-esapi.xml");
		        }
			}
		} catch( Exception e ) {
			new ValidationException( "Could not initialize AntiSamy", "AntiSamy policy failure", e );
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
	
	public Object getValid( String context, String input ) throws ValidationException {
		return invokeAntiSamy( context, input, true );
	}
		
	public Object sanitize( String context, String input ) {
		String safe = "";
		try {
			safe = invokeAntiSamy( context, input, false );
		} catch( ValidationException e ) {
			// just return safe
		}
		return safe;
	}

	private String invokeAntiSamy( String context, String input, boolean throwException ) throws ValidationException {
		// check null
	    if ( input == null || input.length()==0 ) {
			if (allowNull) return null;
			throw new ValidationException( context + " is required", "AntiSamy validation error: context=" + context + ", input=" + input, context );
	    }
	    
		String canonical = (String)super.getValid( context, input );

		try {
			AntiSamy as = new AntiSamy();
			CleanResults test = as.scan(canonical, antiSamyPolicy);
			
			List errors = test.getErrorMessages();
			if ( errors.size() > 0 ) {
				logger.info( Logger.EVENT_SUCCESS, "Cleaned up invalid HTML input: " + errors );
			}
			
			return(test.getCleanHTML().trim());
			
		} catch (ScanException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input: context=" + context + " error=" + e.getMessage(), e, context );
		} catch (PolicyException e) {
			throw new ValidationException( context + ": Invalid HTML input", "Invalid HTML input does not follow rules in antisamy-esapi.xml: context=" + context + " error=" + e.getMessage(), e, context );
		}
	}
}

