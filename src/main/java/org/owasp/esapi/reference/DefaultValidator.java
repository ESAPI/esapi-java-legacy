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
import java.net.URI;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
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
 * Reference implementation of the {@code Validator} interface. This implementation
 * relies on the ESAPI {@code Encoder}, {@link java.util.regex.Pattern},
 * {@link java.util.Date},
 * and several other classes to provide basic validation functions. This library
 * has a heavy emphasis on allow-list validation and canonicalization.
 * <p>
 * <b>A Note about Canonicalization</b>:
 * The behaviors of objects of this class are largely driven by how the
 * associated {@code Encoder} is created and passed to one of this
 * class' constructors. Specifically, what {@link org.owasp.esapi.codecs.Codec}
 * types are referenced by the {@link org.owasp.esapi.Encoder} instance
 * associated with this particular {@code DefaultValidator} instance. In places
 * where the default {@code Encoder} instance is used, the behavior is driven
 * by three ESAPI properties as defined in the <b>ESAPI.properties</b> file.
 * These property names and their default values (as delivered in ESAPI's
 * "configuration" jar) are as follows:
 * <pre>
 * Encoder.AllowMultipleEncoding=false
 * Encoder.AllowMixedEncoding=false
 * Encoder.DefaultCodecList=HTMLEntityCodec,PercentCodec,JavaScriptCodec
 * </pre>
 * In places where canonicalization is checked, multiple
 * encoding (the first property, which refers to encoding in the <i>same</i> manner
 * more than once) or mixed encoding (the second property, which refers to
 * encoding using multiple <i>different</i> encoding mechanisms) are generally
 * considered attacks unless these respective property values are set to
 * "true".
 * </p><p>
 * Note that changing any of these three properties may affect the behavior as
 * documented in this class' methods.
 * </p>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Jim Manico (jim@manico.net) <a href="http://www.manico.net">Manico.net</a>
 * @author Matt Seil (mseil .at. acm.org)
 *
 * @since June 1, 2007
 * @see org.owasp.esapi.Validator
 * @see org.owasp.esapi.Encoder
 * @see org.owasp.esapi.Encoder#canonicalize(String,boolean,boolean)
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

    /* Initialize file validator with an appropriate set of codecs */
    static {
        List<String> list = new ArrayList<String>();
        list.add( "HTMLEntityCodec" );
        list.add( "PercentCodec" );
        Encoder fileEncoder = new DefaultEncoder( list );
        fileValidator = new DefaultValidator( fileEncoder );
    }


    /**
     * Default constructor uses the ESAPI standard encoder for canonicalization.
     * This uses an {@code Encoder} created based on the {@code Codec}s
     * specified by the value of the {@code Encoder.DefaultCodecList} ESAPI
     * property as defined in your <b>ESAPI.properties</b> file.
     */
    public DefaultValidator() {
        this.encoder = ESAPI.encoder();
    }

    /**
     * Construct a new DefaultValidator that will use the specified
     * {@code Encoder} for canonicalization.
     * @param encoder The specially constructed ESAPI {@code Encoder} instance
     *                that uses a custom list of {@code Codec}s for
     *                canonicalization purposes. See
     *                {@link org.owasp.esapi.Encoder#canonicalize(String,boolean,boolean)}
     *                for an example of how to create a custom {@code Encoder}.
     */
    public DefaultValidator( Encoder encoder ) {
        this.encoder = encoder;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addRule(ValidationRule rule ) {
        rules.put( rule.getTypeName(), rule );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ValidationRule getRule(String name ) {
        return rules.get( name );
    }


    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
    public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException  {
        return isValidInput(context, input, type, maxLength, allowNull, true);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
    public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errors)  {
        return isValidInput(context, input, type, maxLength, allowNull, true, errors);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) {
        try {
            getValidInput( context, input, type, maxLength, allowNull, canonicalize);
            return true;
        } catch( Exception e ) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
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
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
    public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException {
        return getValidInput(context, input, type, maxLength, allowNull, true);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
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
        rvr.setCanonicalize(canonicalize);
        return rvr.getValid(context, input);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
    public String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        return getValidInput(context, input, type, maxLength, allowNull, true, errors);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Double encoding is treated as an attack.
     * The canonicalization behavior is controlled by the instance's associated ESAPI
     * {@code Encoder} and generally driven through the ESAPI property
     * {@code Encoder.DefaultCodecList} specified in the <b>ESAPI.properties</b>
     * file. See the class level documentation section "<b>A Note about Canonicalization</b>"
     * for additional details.
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) {
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
    @Override
    public boolean isValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        getValidDate( context, input, format, allowNull, errors);
        return errors.isEmpty();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException {

        ValidationErrorList vel = new ValidationErrorList();
        Date validDate =  getValidDate(context, input, format, allowNull, vel);

        if (vel.isEmpty()) {
            return validDate;
        }

        throw vel.errors().get(0);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        DateValidationRule dvr = new DateValidationRule( "SimpleDate", encoder, format);
        dvr.setAllowNull(allowNull);
        Date safeDate = dvr.sanitize(context, input, errors);
        if (!errors.isEmpty()) {
            safeDate = null;
        }
        // error has been added to list, so return null
        return safeDate;
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) {
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
    @Override
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
     * <p>
     * This implementation relies on the <a href="https://owasp.org/www-project-antisamy/">OWASP AntiSamy project</a>.
     */
    @Override
    public String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull ) throws ValidationException, IntrusionException {
        HTMLValidationRule hvr = new HTMLValidationRule( "safehtml", encoder );
        hvr.setMaximumLength(maxLength);
        hvr.setAllowNull(allowNull);
        return hvr.getValid(context, input);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidCreditCard(String context, String input, boolean allowNull) {
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
    @Override
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
    @Override
    public String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
        CreditCardValidationRule ccvr = new CreditCardValidationRule( "creditcard", encoder );
        ccvr.setAllowNull(allowNull);
        return ccvr.getValid(context, input);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull) {
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
    @Override
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
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
     * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
     * path (/private/etc), not the symlink (/etc).</p>
     */
    @Override
    public String getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws ValidationException, IntrusionException {
        try {
            if (isEmpty(input)) {
                if (allowNull) {
                    return null;
                }
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
            if ( !dir.getCanonicalFile().toPath().startsWith( parent.getCanonicalFile().toPath() ) ) { // Fixes GHSL-2022-008
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
     *
     * <p><b>Note:</b> On platforms that support symlinks, this function will fail canonicalization if directorypath
     * is a symlink. For example, on MacOS X, /etc is actually /private/etc. If you mean to use /etc, use its real
     * path (/private/etc), not the symlink (/etc).</p>
     */
    @Override
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
    @Override
    public boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException {
        return isValidFileName( context, input, ESAPI.securityConfiguration().getAllowedFileExtensions(), allowNull );
    }

    /**
     * {@inheritDoc}
     */
    @Override   
    public boolean isValidFileName(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        return isValidFileName( context, input, ESAPI.securityConfiguration().getAllowedFileExtensions(), allowNull, errors );
    }

    /**
     * {@inheritDoc}
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) {
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
    @Override
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
    @Override
    public String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException {
        if ((allowedExtensions == null) || (allowedExtensions.isEmpty())) {
            throw new ValidationException( "Internal Error", "getValidFileName called with an empty or null list of allowed Extensions, therefore no files can be uploaded" );
        }

        String canonical = "";
        // detect path manipulation
        try {
            if (isEmpty(input)) {
                if (allowNull) {
                    return null;
                }
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
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) {
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
    @Override
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
    @Override
    public Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException {
        Double minDoubleValue = new Double(minValue);
        Double maxDoubleValue = new Double(maxValue);
        return getValidDouble(context, input, minDoubleValue.doubleValue(), maxDoubleValue.doubleValue(), allowNull);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) {
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
    @Override
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
    @Override
    public Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException {
        NumberValidationRule nvr = new NumberValidationRule( "number", encoder, minValue, maxValue );
        nvr.setAllowNull(allowNull);
        return nvr.getValid(context, input);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
    @Override
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
    @Override
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
    @Override
    public Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException {
        IntegerValidationRule ivr = new IntegerValidationRule( "number", encoder, minValue, maxValue );
        ivr.setAllowNull(allowNull);
        return ivr.getValid(context, input);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
    public boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) {
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
    @Override
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
    @Override
    public byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException {
        if (isEmpty(input)) {
            if (allowNull) {
                return null;
            }
            throw new ValidationException( context + ": Input required", "Input required: context=" + context + ", input=" + Arrays.toString(input), context );
        }

        long esapiMaxBytes = ESAPI.securityConfiguration().getAllowedFileUploadSize();
        if (input.length > esapiMaxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + esapiMaxBytes + " bytes", "Exceeded ESAPI max length", context );
        if (input.length > maxBytes ) throw new ValidationException( context + ": Invalid file content can not exceed " + maxBytes + " bytes", "Exceeded maxBytes ( " + input.length + ")", context );

        return input;
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
    @Override
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
    @Override
    public boolean isValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        return( isValidFileName( context, filename, allowNull, errors ) &&
                isValidDirectoryPath( context, directorypath, parent, allowNull, errors ) &&
                isValidFileContent( context, content, maxBytes, allowNull, errors ) );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void assertValidFileUpload(String context, String directorypath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException {
        getValidFileName( context, filename, allowedExtensions, allowNull );
        getValidDirectoryPath( context, directorypath, parent, allowNull );
        getValidFileContent( context, content, maxBytes, allowNull );
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
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
     */
    @Override
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
     * {@inheritDoc}
     */
    @Override
    public String getValidListItem(String context, String input, List<String> list) throws ValidationException, IntrusionException {
        if (list.contains(input)) return input;
        throw new ValidationException( context + ": Invalid list item", "Invalid list item: context=" + context + ", input=" + input, context );
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     */
    @Override
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
    @Override
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
     * {@inheritDoc}
     */
    @Override
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
     * {@inheritDoc}
     */
    @Override
    public void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errors) throws IntrusionException {
        try {
            assertValidHTTPRequestParameterSet(context, request, required, optional);
        } catch (ValidationException e) {
            errors.addError(context, e);
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks that all bytes are valid ASCII characters (between 33 and 126 inclusive).
     * This implementation does no decoding.
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull) {
        try {
            getValidPrintable( context, input, maxLength, allowNull);
            return true;
        } catch( Exception e ) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks that all bytes are valid ASCII characters (between 33 and 126
     * inclusive). This implementation does no decoding.
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
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
     * {@inheritDoc}
     * <p>
     * Input is valid if it only contains printable ASCII characters (33-126 inclusive).
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException {
        if (isEmpty(input)) {
            if (allowNull) {
                return null;
            }
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
     * {@inheritDoc}
     * <p>
     * Input is valid if it only contains printable ASCII characters (33-126 inclusive).
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errors)
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
     * <p>
     * Returns true if input is valid printable ASCII characters (33-126 inclusive).
     * <p>
     * This implementation does not throw {@link IntrusionException}.
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) {
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
     * Returns true if input is valid printable ASCII characters (33-126 inclusive).
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
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
     * {@inheritDoc}
     * <p>
     * Input is valid if it only contains printable ASCII characters (33-126 inclusive).
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException {
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
     * {@inheritDoc}
     *
     * Input is valid if it only contains printable ASCII characters (33-126 inclusive).
     *
     * @see <a href="https://en.wikipedia.org/wiki/ASCII">Wikipedia - ASCII</a>
     */
    @Override
    public String getValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
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
     */
    @Override
    public boolean isValidRedirectLocation(String context, String input, boolean allowNull) throws IntrusionException {
        SecurityConfiguration sc = ESAPI.securityConfiguration();
        return ESAPI.validator().isValidInput( context, input, "Redirect", sc.getIntProp("HttpUtilities.maxRedirectLength"), allowNull);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errors) throws IntrusionException {
        SecurityConfiguration sc = ESAPI.securityConfiguration();
        return ESAPI.validator().isValidInput( context, input, "Redirect", sc.getIntProp("HttpUtilities.maxRedirectLength"), allowNull, errors);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException {
        SecurityConfiguration sc = ESAPI.securityConfiguration();
        return ESAPI.validator().getValidInput( context, input, "Redirect", sc.getIntProp("HttpUtilities.maxRedirectLength"), allowNull);
    }

    /**
     * {@inheritDoc}
     */
    @Override
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
     * <p>
     * This implementation reads until a newline or the specified number of
     * characters.
     */
    @Override
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
    @Override
    public boolean isValidURI(String context, String input, boolean allowNull) {
        boolean isValid = false;
        boolean inputIsNullOrEmpty = input == null || "".equals(input);
        Encoder encoder = ESAPI.encoder();
        try{
            URI compliantURI = null == input ? new URI("") :  this.getRfcCompliantURI(input);
            if(null != compliantURI && input != null){
                String canonicalizedURI = encoder.getCanonicalizedURI(compliantURI);
                //if getCanonicalizedURI doesn't throw an IntrusionException, then the URI contains no mixed or
                //double-encoding attacks.
                logger.debug(Logger.SECURITY_SUCCESS, "We did not detect any mixed or multiple encoding in the uri:[" + input + "]");
                Validator v = ESAPI.validator();
                //This part will use the regex from validation.properties.  This regex should be super-simple, and
                //used mainly to restrict certain parts of a URL.
                Pattern p = ESAPI.securityConfiguration().getValidationPattern( "URL" );
                if(p != null){
                    //We're doing this instead of using the normal validator API, because it will canonicalize the input again
                    //and if the URI has any queries that also happen to match HTML entities, like &para;
                    //it will cease conforming to the regex we now specify for a URL.
                    isValid = p.matcher(canonicalizedURI).matches();
                }else{
                    logger.error(Logger.EVENT_FAILURE, "Invalid regex pulled from configuration.  Check the regex for URL and correct.");
                }
            }else{
                if(allowNull && inputIsNullOrEmpty ){
                    isValid = true;
                }
            }

        }catch (IntrusionException e){
            logger.error(Logger.SECURITY_FAILURE, e.getMessage());
            isValid = false;
        } catch (URISyntaxException e) {
            logger.error(Logger.EVENT_FAILURE, e.getMessage());
        }


        return isValid;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public URI getRfcCompliantURI(String input){
        URI rval = null;
        try {
            rval = new URI(input);
        } catch (URISyntaxException e) {
            logger.error(Logger.EVENT_FAILURE, e.getMessage());
        }
        return rval;
    }
}
