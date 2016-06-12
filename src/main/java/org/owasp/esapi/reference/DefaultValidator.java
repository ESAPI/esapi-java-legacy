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
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 *
 * @created 2007
 */
package org.owasp.esapi.reference;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ValidationRule;
import org.owasp.esapi.Validator;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationAvailabilityException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.validation.CreditCardValidationRule;
import org.owasp.esapi.reference.validation.DateValidationRule;
import org.owasp.esapi.reference.validation.HTMLValidationRule;
import org.owasp.esapi.reference.validation.IntegerValidationRule;
import org.owasp.esapi.reference.validation.NumberValidationRule;
import org.owasp.esapi.reference.validation.StringValidationRule;

/**
 * Reference implementation of the Validator interface. This implementation
 * relies on the ESAPI Encoder, Java Pattern (regex), Date,
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on whitelist validation and canonicalization.
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 *
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 */
public class DefaultValidator implements org.owasp.esapi.Validator {
	private static Logger logger = ESAPI.log();
    private static volatile Validator instance = null;

    public static Validator getInstance() {
        if ( instance == null ) {
            synchronized ( Validator.class ) {
                if ( instance == null ) {
                    instance = new DefaultValidator();
                }
            }
        }
        return instance;
    }

	/** A map of validation rules */
	private Map<String, ValidationRule> rules = new HashMap<String, ValidationRule>();

	/** The encoder to use for canonicalization */
	private Encoder encoder = null;

	/** The encoder to use for file system */
	private static Validator fileValidator = null;

	/** Initialize file validator with an appropriate set of codecs */
	static {
		List<String> list = new ArrayList<String>();
		list.add( "HTMLEntityCodec" );
		list.add( "PercentCodec" );
		Encoder fileEncoder = new DefaultEncoder( list );
		fileValidator = new DefaultValidator( fileEncoder );
	}


	/**
	 * Default constructor uses the ESAPI standard encoder for canonicalization.
	 */
	public DefaultValidator() {
	    this.encoder = ESAPI.encoder();
	}

	/**
	 * Construct a new DefaultValidator that will use the specified
	 * Encoder for canonicalization.
     *
     * @param encoder
     */
	public DefaultValidator( Encoder encoder ) {
	    this.encoder = encoder;
	}


	/**
	 * Add a validation rule to the registry using the "type name" of the rule as the key.
	 */
	public void addRule( ValidationRule rule ) {
		rules.put( rule.getTypeName(), rule );
	}

	/**
	 * Get a validation rule from the registry with the "type name" of the rule as the key.
	 */
	public ValidationRule getRule( String name ) {
		return rules.get( name );
	}


	/**
	 * Returns true if data received from browser is valid. Double encoding is treated as an attack. The
	 * default encoder supports html encoding, URL encoding, and javascript escaping. Input is canonicalized
	 * by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException  {
		return isValidInput(context, input, type, maxLength, allowNull, true);
	}

        public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException  {
		return isValidInput(context, input, type, maxLength, allowNull, true, errors);
	}

	public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws IntrusionException  {
		try {
			getValidInput( context, input, type, maxLength, allowNull, canonicalize);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errors) throws IntrusionException  {
		try {
			getValidInput( context, input, type, maxLength, allowNull, canonicalize);
			return true;
		} catch( ValidationException e ) {
			errors.addError( context, e );
			return false;
		}
	}

	/**
	 * Validates data received from the browser and returns a safe version.
	 * Double encoding is treated as an attack. The default encoder supports
	 * html encoding, URL encoding, and javascript escaping. Input is
	 * canonicalized by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name which maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed.
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @return The canonicalized user input.
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException {
		return getValidInput(context, input, type, maxLength, allowNull, true);
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name which maps to the actual regular expression in the ESAPI validation configuration file
	 * @param maxLength The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization
     * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize If canonicalize is true then input will be canonicalized before validation
	 * @return The user input, may be canonicalized if canonicalize argument is true
	 * @throws ValidationException
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException {
		StringValidationRule rvr = new StringValidationRule( type, encoder );
		Pattern p = ESAPI.securityConfiguration().getValidationPattern( type );
		if ( p != null ) {
			rvr.addWhitelistPattern( p );
		} else {
            // Issue 232 - Specify requested type in exception message - CS
			throw new IllegalArgumentException("The selected type [" + type + "] was not set via the ESAPI validation configuration");
		}
		rvr.setMaximumLength(maxLength);
		rvr.setAllowNull(allowNull);
		rvr.setValidateInputAndCanonical(canonicalize);
		return rvr.getValid(context, input);
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack. Input
	 * is canonicalized by default before validation.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum String length allowed. If input is canonicalized per the canonicalize argument, then maxLength must be verified after canonicalization
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The canonicalized user input.
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		return getValidInput(context, input, type, maxLength, allowNull, true, errors);
	}

	/**
	 * Validates data received from the browser and returns a safe version. Only
	 * URL encoding is supported. Double encoding is treated as an attack.
	 *
	 * @param context A descriptive name for the field to validate. This is used for error facing validation messages and element identification.
	 * @param input The actual user input data to validate.
	 * @param type The regular expression name while maps to the actual regular expression from "ESAPI.properties".
	 * @param maxLength The maximum post-canonicalized String length allowed
	 * @param allowNull If allowNull is true then a input that is NULL or an empty string will be legal. If allowNull is false then NULL or an empty String will throw a ValidationException.
	 * @param canonicalize If canonicalize is true then input will be canonicalized before validation
	 * @param errors If ValidationException is thrown, then add to error list instead of throwing out to caller
	 * @return The user input, may be canonicalized if canonicalize argument is true
	 * @throws IntrusionException
	 */
	public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidInput(context,  input,  type,  maxLength,  allowNull, canonicalize);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return "";
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException {
		try {
			getValidDate( context, input, format, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidDate( context, input, format, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException {
		DateValidationRule dvr = new DateValidationRule( "SimpleDate", encoder, format);
		dvr.setAllowNull(allowNull);
		return dvr.getValid(context, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidDate(context, input, format, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return null
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidSafeHTML( context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidSafeHTML( context, input, maxLength, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 *
	 * This implementation relies on the OWASP AntiSamy project.
	 */
	public String getValidSafeHTML( String context, String input, int maxLength, boolean allowNull ) throws ValidationException, IntrusionException {
		HTMLValidationRule hvr = new HTMLValidationRule( "safehtml", encoder );
		hvr.setMaximumLength(maxLength);
		hvr.setAllowNull(allowNull);
		hvr.setValidateInputAndCanonical(false);
		return hvr.getValid(context, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidSafeHTML(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return "";
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException {
		try {
			getValidCreditCard( context, input, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidCreditCard( context, input, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}
	/**
	 * {@inheritDoc}
	 */
	public String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		CreditCardValidationRule ccvr = new CreditCardValidationRule( "creditcard", encoder );
		ccvr.setAllowNull(allowNull);
		return ccvr.getValid(context, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidCreditCard(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return "";
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	public boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws IntrusionException {
		try {
			getValidDirectoryPath( context, input, parent, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
	 */
	public boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidDirectoryPath( context, input, parent, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}
	/**
	 * {@inheritDoc}
	 */
	public String getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws ValidationException, IntrusionException {
		try {
			if (isEmpty(input)) {
				if (allowNull) return null;
       			throw new ValidationException( context + ": Input directory path required", "Input directory path required: context=" + context + ", input=" + input, context );
			}

			File dir = new File( input );

			// check dir exists and parent exists and dir is inside parent
			if ( !dir.exists() ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory, does not exist: context=" + context + ", input=" + input );
			}
			if ( !dir.isDirectory() ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory, not a directory: context=" + context + ", input=" + input );
			}
			if ( !parent.exists() ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory, specified parent does not exist: context=" + context + ", input=" + input + ", parent=" + parent );
			}
			if ( !parent.isDirectory() ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory, specified parent is not a directory: context=" + context + ", input=" + input + ", parent=" + parent );
			}
			if ( !dir.getCanonicalPath().startsWith(parent.getCanonicalPath() ) ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory, not inside specified parent: context=" + context + ", input=" + input + ", parent=" + parent );
			}

			// check canonical form matches input
			String canonicalPath = dir.getCanonicalPath();
			String canonical = fileValidator.getValidInput( context, canonicalPath, "DirectoryName", 255, false);
			if ( !canonical.equals( input ) ) {
				throw new ValidationException( context + ": Invalid directory name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context );
			}
			return canonical;
		} catch (Exception e) {
			throw new ValidationException( context + ": Invalid directory name", "Failure to validate directory path: context=" + context + ", input=" + input, e, context );
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public String getValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errors) throws IntrusionException {

		try {
			return getValidDirectoryPath(context, input, parent, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return "";
	}


	/**
	 * {@inheritDoc}
	 */
	public boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException {
		return isValidFileName( context, input, ESAPI.securityConfiguration().getAllowedFileExtensions(), allowNull );
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidFileName(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		return isValidFileName( context, input, ESAPI.securityConfiguration().getAllowedFileExtensions(), allowNull, errors );
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws IntrusionException {
		try {
			getValidFileName( context, input, allowedExtensions, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidFileName( context, input, allowedExtensions, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}
	/**
	 * {@inheritDoc}
	 */
	public String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException {
		if ((allowedExtensions == null) || (allowedExtensions.isEmpty())) {
			throw new ValidationException( "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" );
		}

		String canonical = "";
		// detect path manipulation
		try {
			if (isEmpty(input)) {
				if (allowNull) return null;
	   			throw new ValidationException( context + ": Input file name required", "Input required: context=" + context + ", input=" + input, context );
			}

			// do basic validation
	        canonical = new File(input).getCanonicalFile().getName();
	        getValidInput( context, input, "FileName", 255, true );

			File f = new File(canonical);
			String c = f.getCanonicalPath();
			String cpath = c.substring(c.lastIndexOf(File.separator) + 1);


			// the path is valid if the input matches the canonical path
			if (!input.equals(cpath)) {
				throw new ValidationException( context + ": Invalid file name", "Invalid directory name does not match the canonical path: context=" + context + ", input=" + input + ", canonical=" + canonical, context );
			}

		} catch (IOException e) {
			throw new ValidationException( context + ": Invalid file name", "Invalid file name does not exist: context=" + context + ", canonical=" + canonical, e, context );
		}

		// verify extensions
		Iterator<String> i = allowedExtensions.iterator();
		while (i.hasNext()) {
			String ext = i.next();
			if (input.toLowerCase().endsWith(ext.toLowerCase())) {
				return canonical;
			}
		}
		throw new ValidationException( context + ": Invalid file name does not have valid extension ( "+allowedExtensions+")", "Invalid file name does not have valid extension ( "+allowedExtensions+"): context=" + context+", input=" + input, context );
	}

	/**
	 * {@inheritDoc}
	 */
	public String getValidFileName(String context, String input, List<String> allowedParameters, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidFileName(context, input, allowedParameters, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return "";
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException {
		try {
			getValidNumber(context, input, minValue, maxValue, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidNumber(context, input, minValue, maxValue, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		Double minDoubleValue = new Double(minValue);
		Double maxDoubleValue = new Double(maxValue);
		return getValidDouble(context, input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), allowNull);
	}

	/**
	 * {@inheritDoc}
	 */
	public Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidNumber(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException {
        try {
            getValidDouble( context, input, minValue, maxValue, allowNull );
            return true;
        } catch( Exception e ) {
            return false;
        }
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        try {
            getValidDouble( context, input, minValue, maxValue, allowNull );
            return true;
        } catch( ValidationException e ) {
            errors.addError(context, e);
            return false;
        }
	}

	/**
	 * {@inheritDoc}
	 */
	public Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		NumberValidationRule nvr = new NumberValidationRule( "number", encoder, minValue, maxValue );
		nvr.setAllowNull(allowNull);
		return nvr.getValid(context, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidDouble(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}

		return new Double(Double.NaN);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException {
		try {
			getValidInteger( context, input, minValue, maxValue, allowNull);
			return true;
		} catch( ValidationException e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidInteger( context, input, minValue, maxValue, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException {
		IntegerValidationRule ivr = new IntegerValidationRule( "number", encoder, minValue, maxValue );
		ivr.setAllowNull(allowNull);
		return ivr.getValid(context, input);
	}

	/**
	 * {@inheritDoc}
	 */
	public Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidInteger(context, input, minValue, maxValue, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return original input
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException {
		try {
			getValidFileContent( context, input, maxBytes, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 */
	public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidFileContent( context, input, maxBytes, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException( context + ": Input required", "Input required: context=" + context + ", input=" + input, context );
		}

		long esapiMaxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
		if (input.length > esapiMaxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + esapiMaxBytes + " bytes", "Exceeded ESAPI max length", context );
		if (input.length > maxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + maxBytes + " bytes", "Exceeded maxBytes ( " + input.length + ")", context );

		return input;
	}

	/**
	 * {@inheritDoc}
	 */
	public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidFileContent(context, input, maxBytes, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// return empty byte array on error
		return new byte[0];
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
     */
	public boolean isValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException {
		return( isValidFileName( context, filename, allowNull ) &&
				isValidDirectoryPath( context, directorypath, parent, allowNull ) &&
				isValidFileContent( context, content, maxBytes, allowNull ) );
	}

        /**
	 * {@inheritDoc}
	 *
	 * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
	 * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
	 * path (/private/etc), not the symlink (/etc).</p>
     */
	public boolean isValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		return( isValidFileName( context, filename, allowNull, errors ) &&
				isValidDirectoryPath( context, directorypath, parent, allowNull, errors ) &&
				isValidFileContent( context, content, maxBytes, allowNull, errors ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public void assertValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException {
		getValidFileName( context, filename, allowedExtensions, allowNull );
		getValidDirectoryPath( context, directorypath, parent, allowNull );
		getValidFileContent( context, content, maxBytes, allowNull );
	}

	/**
	 * {@inheritDoc}
	 */
	public void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errors)
		throws IntrusionException {
		try {
			assertValidFileUpload(context, filepath, filename, parent, content, maxBytes, allowedExtensions, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
	}

	 /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is a valid list item.
	 */
	public boolean isValidListItem(String context, String input, List<String> list) {
		try {
			getValidListItem( context, input, list);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is a valid list item.
	 */
	public boolean isValidListItem(String context, String input, List<String> list, ValidationErrorList errors) {
		try {
			getValidListItem( context, input, list);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * Returns the list item that exactly matches the canonicalized input. Invalid or non-matching input
	 * will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	public String getValidListItem(String context, String input, List<String> list) throws ValidationException, IntrusionException {
		if (list.contains(input)) return input;
		throw new ValidationException( context + ": Invalid list item", "Invalid list item: context=" + context + ", input=" + input, context );
	}


	/**
	 * ValidationErrorList variant of getValidListItem
     *
     * @param errors
     */
	public String getValidListItem(String context, String input, List<String> list, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidListItem(context, input, list);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return original input
		return input;
	}

	 /**
	 * {@inheritDoc}
     */
	public boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames) {
		try {
			assertValidHTTPRequestParameterSet( context, request, requiredNames, optionalNames);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

         /**
	 * {@inheritDoc}
     */
	public boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> requiredNames, Set<String> optionalNames, ValidationErrorList errors) {
		try {
			assertValidHTTPRequestParameterSet( context, request, requiredNames, optionalNames);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * Validates that the parameters in the current request contain all required parameters and only optional ones in
	 * addition. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 *
	 * Uses current HTTPRequest
	 */
	public void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException, IntrusionException {
		Set<String> actualNames = request.getParameterMap().keySet();

		// verify ALL required parameters are present
		Set<String> missing = new HashSet<String>(required);
		missing.removeAll(actualNames);
		if (missing.size() > 0) {
			throw new ValidationException( context + ": Invalid HTTP request missing parameters", "Invalid HTTP request missing parameters " + missing + ": context=" + context, context );
		}

		// verify ONLY optional + required parameters are present
		Set<String> extra = new HashSet<String>(actualNames);
		extra.removeAll(required);
		extra.removeAll(optional);
		if (extra.size() > 0) {
			throw new ValidationException( context + ": Invalid HTTP request extra parameters " + extra, "Invalid HTTP request extra parameters " + extra + ": context=" + context, context );
		}
	}

	/**
	 * ValidationErrorList variant of assertIsValidHTTPRequestParameterSet
     *
	 * Uses current HTTPRequest saved in ESAPI Authenticator
     * @param errors
     */
	public void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errors) throws IntrusionException {
		try {
			assertValidHTTPRequestParameterSet(context, request, required, optional);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
	}

	/**
     * {@inheritDoc}
     *
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	 */
	public boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
     * {@inheritDoc}
     *
	 * Checks that all bytes are valid ASCII characters (between 33 and 126
	 * inclusive). This implementation does no decoding. http://en.wikipedia.org/wiki/ASCII.
	 */
	public boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * Returns canonicalized and validated printable characters as a byte array. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @throws IntrusionException
     */
	public char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		if (isEmpty(input)) {
			if (allowNull) return null;
   			throw new ValidationException(context + ": Input bytes required", "Input bytes required: HTTP request is null", context );
		}

		if (input.length > maxLength) {
			throw new ValidationException(context + ": Input bytes can not exceed " + maxLength + " bytes", "Input exceeds maximum allowed length of " + maxLength + " by " + (input.length-maxLength) + " bytes: context=" + context + ", input=" + new String( input ), context);
		}

		for (int i = 0; i < input.length; i++) {
			if (input[i] <= 0x20 || input[i] >= 0x7E ) {
				throw new ValidationException(context + ": Invalid input bytes: context=" + context, "Invalid non-ASCII input bytes, context=" + context + ", input=" + new String( input ), context);
			}
		}
		return input;
	}

	/**
	 * ValidationErrorList variant of getValidPrintable
     *
     * @param errors
     */
	public char[] getValidPrintable(String context, char[] input,int maxLength, boolean allowNull, ValidationErrorList errors)
		throws IntrusionException {

		try {
			return getValidPrintable(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return original input
		return input;
	}


	 /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is valid printable ASCII characters (32-126).
	 */
	public boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( Exception e ) {
			return false;
		}
	}

        /**
	 * {@inheritDoc}
	 *
	 * Returns true if input is valid printable ASCII characters (32-126).
	 */
	public boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			getValidPrintable( context, input, maxLength, allowNull);
			return true;
		} catch( ValidationException e ) {
            errors.addError(context, e);
			return false;
		}
	}

	/**
	 * Returns canonicalized and validated printable characters as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
     *
     * @throws IntrusionException
     */
	public String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
		try {
    		String canonical = encoder.canonicalize(input);
    		return new String( getValidPrintable( context, canonical.toCharArray(), maxLength, allowNull) );
	    //TODO - changed this to base Exception since we no longer need EncodingException
    	//TODO - this is a bit lame: we need to re-think this function.
		} catch (Exception e) {
	        throw new ValidationException( context + ": Invalid printable input", "Invalid encoding of printable input, context=" + context + ", input=" + input, e, context);
	    }
	}

	/**
	 * ValidationErrorList variant of getValidPrintable
     *
     * @param errors
     */
	public String getValidPrintable(String context, String input,int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidPrintable(context, input, maxLength, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return original input
		return input;
	}


	/**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean isValidRedirectLocation(String context, String input, boolean allowNull) throws IntrusionException {
		return ESAPI.validator().isValidInput( context, input, "Redirect", 512, allowNull);
	}

        /**
	 * Returns true if input is a valid redirect location.
	 */
	public boolean isValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		return ESAPI.validator().isValidInput( context, input, "Redirect", 512, allowNull, errors);
	}


	/**
	 * Returns a canonicalized and validated redirect location as a String. Invalid input will generate a descriptive ValidationException, and input that is clearly an attack
	 * will generate a descriptive IntrusionException.
	 */
	public String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
		return ESAPI.validator().getValidInput( context, input, "Redirect", 512, allowNull);
	}

	/**
	 * ValidationErrorList variant of getValidRedirectLocation
     *
     * @param errors
     */
	public String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
		try {
			return getValidRedirectLocation(context, input, allowNull);
		} catch (ValidationException e) {
			errors.addError(context, e);
		}
		// error has been added to list, so return original input
		return input;
	}

	/**
     * {@inheritDoc}
     *
	 * This implementation reads until a newline or the specified number of
	 * characters.
     *
     * @param in
     * @param max
     */
	public String safeReadLine(InputStream in, int max) throws ValidationException {
		if (max <= 0) {
			throw new ValidationAvailabilityException( "Invalid input", "Invalid readline. Must read a positive number of bytes from the stream");
		}

		StringBuilder sb = new StringBuilder();
		int count = 0;
		int c;

		try {
			while (true) {
				c = in.read();
				if ( c == -1 ) {
					if (sb.length() == 0) {
						return null;
					}
					break;
				}
				if (c == '\n' || c == '\r') {
					break;
				}
				count++;
				if (count > max) {
					throw new ValidationAvailabilityException( "Invalid input", "Invalid readLine. Read more than maximum characters allowed (" + max + ")");
				}
				sb.append((char) c);
			}
			return sb.toString();
		} catch (IOException e) {
			throw new ValidationAvailabilityException( "Invalid input", "Invalid readLine. Problem reading from input stream", e);
		}
	}

	/**
	 * Helper function to check if a String is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private final boolean isEmpty(String input) {
		return (input==null || input.trim().length() == 0);
	}

	/**
	 * Helper function to check if a byte array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private final boolean isEmpty(byte[] input) {
		return (input==null || input.length == 0);
	}


	/**
	 * Helper function to check if a char array is empty
	 *
	 * @param input string input value
	 * @return boolean response if input is empty or not
	 */
	private final boolean isEmpty(char[] input) {
		return (input==null || input.length == 0);
	}
	
	/**
	 * {@inheritDoc}
	 */
	public boolean isValidURI(String context, String input, boolean allowNull) {
		boolean isValid = false;
		URI compliantURI = this.getRfcCompliantURI(input);
		
		try{
			if(null != compliantURI){
				String canonicalizedURI = getCanonicalizedURI(compliantURI);
				//if getCanonicalizedURI doesn't throw an IntrusionException, then the URI contains no mixed or 
				//double-encoding attacks.  
				logger.info(Logger.SECURITY_SUCCESS, "We did not detect any mixed or multiple encoding in the uri:[" + input + "]");
				Validator v = ESAPI.validator();
				//This part will use the regex from validation.properties.  This regex should be super-simple, and 
				//used mainly to restrict certain parts of a URL.  
				Pattern p = ESAPI.securityConfiguration().getValidationPattern( "URL" );
				//We're doing this instead of using the normal validator API, because it will canonicalize the input again
				//and if the URI has any queries that also happen to match HTML entities, like &para;
				//it will cease conforming to the regex we now specify for a URL.
				isValid = p.matcher(canonicalizedURI).matches();
			}
			
		}catch (IntrusionException e){
			logger.error(Logger.SECURITY_FAILURE, e.getMessage());
			isValid = false;
		}
		
		
		return isValid;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public URI getRfcCompliantURI(String input){
		URI rval = null;
		try {
			rval = new URI(input);
		} catch (URISyntaxException e) {
			logger.error(Logger.EVENT_FAILURE, e.getMessage());
		}
		return rval;
	}
	
	/**
	 * This does alot.  This will extract each piece of a URI according to parse zone, and it will construct 
	 * a canonicalized String representing a version of the URI that is safe to run regex against to it. 
	 * 
	 * @param dirtyUri
	 * @return
	 * @throws IntrusionException
	 */
	public String getCanonicalizedURI(URI dirtyUri) throws IntrusionException{
		
//		From RFC-3986 section 3		
//	      URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//
//	    	      hier-part   = "//" authority path-abempty
//	    	                  / path-absolute
//	    	                  / path-rootless
//	    	                  / path-empty
		
//		   The following are two example URIs and their component parts:
//
//		         foo://example.com:8042/over/there?name=ferret#nose
//		         \_/   \______________/\_________/ \_________/ \__/
//		          |           |            |            |        |
//		       scheme     authority       path        query   fragment
//		          |   _____________________|__
//		         / \ /                        \
//		         urn:example:animal:ferret:nose
		Map<UriSegment, String> parseMap = new EnumMap<UriSegment, String>(UriSegment.class);
		parseMap.put(UriSegment.SCHEME, dirtyUri.getScheme());
		//authority   = [ userinfo "@" ] host [ ":" port ]
		parseMap.put(UriSegment.AUTHORITY, dirtyUri.getRawAuthority());
		parseMap.put(UriSegment.SCHEMSPECIFICPART, dirtyUri.getRawSchemeSpecificPart());
		parseMap.put(UriSegment.HOST, dirtyUri.getHost());
		//if port is undefined, it will return -1
		Integer port = new Integer(dirtyUri.getPort());
		parseMap.put(UriSegment.PORT, port == -1 ? "": port.toString());
		parseMap.put(UriSegment.PATH, dirtyUri.getRawPath());
		parseMap.put(UriSegment.QUERY, dirtyUri.getRawQuery());
		parseMap.put(UriSegment.FRAGMENT, dirtyUri.getRawFragment());
		
		//Now we canonicalize each part and build our string.  
		StringBuilder sb = new StringBuilder();
		
		//Replace all the items in the map with canonicalized versions.
		
		Set<UriSegment> set = parseMap.keySet();
		
		SecurityConfiguration sg = ESAPI.securityConfiguration();
//		boolean restrictMixed = sg.getBooleanProp("AllowMixedEncoding");
//		boolean restrictMultiple = sg.getBooleanProp("AllowMultipleEncoding");
		boolean allowMixed = sg.getAllowMixedEncoding();
		boolean allowMultiple = sg.getAllowMultipleEncoding();
		for(UriSegment seg: set){
			String value = encoder.canonicalize(parseMap.get(seg), allowMultiple, allowMixed);
			value = value == null ? "" : value;
			//In the case of a uri query, we need to break up and canonicalize the internal parts of the query.
			if(seg == UriSegment.QUERY && null != parseMap.get(seg)){
				StringBuilder qBuilder = new StringBuilder();
				try {
					Map<String, List<String>> canonicalizedMap = this.splitQuery(dirtyUri);
					Set<Entry<String, List<String>>> query = canonicalizedMap.entrySet();
					Iterator<Entry<String, List<String>>> i = query.iterator();
					while(i.hasNext()){
						Entry<String, List<String>> e = i.next(); 
						String key = (String) e.getKey();
						String qVal = "";
						List<String> list = (List<String>) e.getValue();
						if(!list.isEmpty()){
							qVal = list.get(0);
						}
						qBuilder.append(key)
						.append("=")
						.append(qVal);
						
						if(i.hasNext()){
							qBuilder.append("&");
						}
					}
					value = qBuilder.toString();
				} catch (UnsupportedEncodingException e) {
					logger.debug(Logger.EVENT_FAILURE, "decoding error when parsing [" + dirtyUri.toString() + "]");
				}
			}
			parseMap.put(seg, value );
		}
		
		return buildUrl(parseMap);
	}
	
/**
 * The meat of this method was taken from StackOverflow:  http://stackoverflow.com/a/13592567/557153
 * It has been modified to return a canonicalized key and value pairing.  
 * 
 * @param java URI
 * @return a map of canonicalized query parameters.  
 * @throws UnsupportedEncodingException
 */
	public Map<String, List<String>> splitQuery(URI uri) throws UnsupportedEncodingException {
	  final Map<String, List<String>> query_pairs = new LinkedHashMap<String, List<String>>();
	  final String[] pairs = uri.getQuery().split("&");
	  for (String pair : pairs) {
	    final int idx = pair.indexOf("=");
	    final String key = idx > 0 ? encoder.canonicalize(pair.substring(0, idx)) : pair;
	    if (!query_pairs.containsKey(key)) {
	      query_pairs.put(key, new LinkedList<String>());
	    }
	    final String value = idx > 0 && pair.length() > idx + 1 ? URLDecoder.decode(pair.substring(idx + 1), "UTF-8") : null;
	    query_pairs.get(key).add(encoder.canonicalize(value));
	  }
	  return query_pairs;
	}
	
	public enum UriSegment {
		AUTHORITY, SCHEME, SCHEMSPECIFICPART, USERINFO, HOST, PORT, PATH, QUERY, FRAGMENT
	}
	
	/**
	 * All the parts should be canonicalized by this point.  This is straightforward assembly.  
	 * 
	 * @param set
	 * @return
	 */
	protected String buildUrl(Map<UriSegment, String> parseMap){
		StringBuilder sb = new StringBuilder();
		sb.append(parseMap.get(UriSegment.SCHEME))
		.append("://")
		//can't use SCHEMESPECIFICPART for this, because we need to canonicalize all the parts of the query.
		//USERINFO is also deprecated.  So we technically have more than we need.  
		.append(parseMap.get(UriSegment.AUTHORITY) == null || parseMap.get(UriSegment.AUTHORITY).equals("") ? "" : parseMap.get(UriSegment.AUTHORITY))
		.append(parseMap.get(UriSegment.PATH) == null || parseMap.get(UriSegment.PATH).equals("") ? ""  : parseMap.get(UriSegment.PATH))
		.append(parseMap.get(UriSegment.QUERY) == null || parseMap.get(UriSegment.QUERY).equals("") 
				? "" : "?" + parseMap.get(UriSegment.QUERY))
		.append((parseMap.get(UriSegment.FRAGMENT) == null) || parseMap.get(UriSegment.FRAGMENT).equals("")
				? "": "#" + parseMap.get(UriSegment.FRAGMENT))
		;
		return sb.toString();
	}
	
}
