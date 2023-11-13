/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Worldwide Application Security Project (OWASP)
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
package org.owasp.esapi;

import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.text.DateFormat;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;


/**
 * The Validator interface defines a set of methods for canonicalizing and
 * validating untrusted input. Implementors should feel free to extend this
 * interface to accommodate their own data formats. Rather than throw exceptions,
 * this interface returns boolean results because not all validation problems
 * are security issues. Boolean returns allow developers to handle both valid
 * and invalid results more cleanly than exceptions.
 * <p>
 * Implementations must adopt a "allow-list" approach to validation where a
 * specific pattern or character set is matched. "Blacklist" approaches that
 * attempt to identify the invalid or disallowed characters are much more likely
 * to allow a bypass with encoding or other tricks.
 * </p><p>
 * <b>CAUTION:</b> There are many methods that take multiple (or only!) {@code String}
 * arguments. Be careful that you do not mix up the order of these, because for
 * some methods such as {@code isValidSafeHTML} if you were to confuse the order of
 * {@code context} and {@code input} arguments, you would not be verifying what
 * you thought you were and it could have serious security consequences as a
 * result. When there are 2 these {@code String} parameters&mdash;{@code context} and
 * {@code input} arguments&mdash;the * {@code context} argument is always first.
 * See the individual method documentation for additional details.
 * </p>
 *
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Validator {

    /**
     * Add a validation rule to the registry using the "type name" of the rule as the key.
     * @param The {@link ValidationRule} to add.
     */
    void addRule( ValidationRule rule );

    /**
     * Get a validation rule from the registry with the "type name" of the rule as the key.
     * @param The "type" name of the {@Vlink ValidationRule} to retrieve.
     */
    ValidationRule getRule( String name );

    /**
     * Returns true if canonicalized input is valid.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)} with {@code canonicalize=true}
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if canonicalized input is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)} with {@code canonicalize=true}
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param errorList The error list to which any {@Code ValidationException} messages are added.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param canonicalize
     *         If true, the {@code input} if first canonicalized before being validated.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid;
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param canonicalize
     *         If true, the {@code input} if first canonicalized before being validated.
     * @param errorList The error list to which any {@Code ValidationException} messages are added.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns the validated, canonicalized {@code input} as a String.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)}
     * with {@code canonicalize=true}.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @throws ValidationException Input is invalid, based on the regex associated with {@code type}.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidInput(String context, String input, String type, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns validated {@code input} as a String with optional canonicalization.
     * <p>
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *        A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *        This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *        The actual user input data to validate.
     * @param type
     *        The regular expression name which maps to the actual regular expression from "ESAPI.properties".
     * @param maxLength
     *        The maximum post-canonicalized String length allowed.
     * @param allowNull
     *        If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *        If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param canonicalize
     *        If canonicalize is true then input will be canonicalized before validation.
     *
     * @return The canonicalized user input.
     *
     * @throws ValidationException Input is invalid, based on the regex associated with {@code type}.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize) throws ValidationException, IntrusionException;

    /**
     * Returns canonicalized validated {@code input} as a String,
     * and adds validation exceptions to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidInput(String, String, String, int, boolean, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns validated {@code input} as a String with optional canonicalization,
     * and adds validation exceptions to the supplied {@code errorList}.
     * <p>
     * Returns the result of calling {@link #getValidInput(String, String, String, int, boolean, boolean)}
     * with {@code canonicalize=true}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidInput(String context, String input, String type, int maxLength, boolean allowNull, boolean canonicalize, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidDate(String, String, DateFormat, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDate(String context, String input, DateFormat format, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDate(String, String, DateFormat, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a valid date as a {@link java.util.Date}.
     * <p>
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param format
     *         Required formatting of date inputted.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid date as a {@link java.util.Date}
     *
     * @throws ValidationException Input is invalid, based on the regex associated with {@code type}.
     * @throws IntrusionException Input likely indicates an attack.
     */
    Date getValidDate(String context, String input, DateFormat format, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a valid date as a {@link java.util.Date},
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDate(String, String, DateFormat, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    Date getValidDate(String context, String input, DateFormat format, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidSafeHTML(String, String, int, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @deprecated Deprecated as of ESAPI 2.5.3.0. This method will be removed in 1 year
     * after this ESAPI 2.5.3.0 release.
     *
     * @see <a href="https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-r68h-jhhj-9jvm">GitHub Security Advisory: Validator.isValidSafeHTML is being deprecated and will be deleted in 1 year</a>
     */
    @Deprecated
    boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidSafeHTML(String, String, int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @deprecated Deprecated as of ESAPI 2.5.3.0. This method will be removed in 1 year
     * after this ESAPI 2.5.3.0 release.
     *
     * @see <a href="https://github.com/ESAPI/esapi-java-legacy/security/advisories/GHSA-r68h-jhhj-9jvm">GitHub Security Advisory: Validator.isValidSafeHTML is being deprecated and will be deleted in 1 year</a>
     */
    @Deprecated
    boolean isValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Canonicalize and then sanitize the input so that it is "safe" for renderinger in an HTML context (i.e., that
     * it does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else). Note that the resulting
     * returned value may omit input that is considered dangerous and cannot be safely sanitized and other input
     * that gets HTML encoded (e.g., a single quote (') might get chaged to "&quot;").
     * <p>
     * The default behavior of this check depends on the {@code antisamy-esapi.xml} AntiSamy policy configuration file
     * (or an alternate filename, specified via the "Validator.HtmlValidationConfigurationFile" property in your
     * {@ESAPI.properties} file. Implementors wishing to alter the AntiSamy policy configuration file should
     * reference the <a href="https://owasp.org/www-project-antisamy/">OWASP AntiSamy project</a> for ideas
     * on how to do HTML validation in a allow-list way, as this is an extremely difficult problem.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A string representing the canonicalized and sanitized input that is safe for rendering in an HTML context.
     *
     * @throws ValidationException Input is invalid, based on the regex associated with {@code type}.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Canonicalize and then sanitize the input so that it is "safe" for renderinger in an HTML context (i.e., that
     * it does not contain unwanted scripts in the body, attributes, CSS, URLs, or anywhere else). Note that the resulting
     * returned value may omit input that is considered dangerous and cannot be safely sanitized and other input
     * that gets HTML encoded (e.g., a single quote (') might get chaged to "&quot;").
     * <p>
     * The default behavior of this check depends on the {@code antisamy-esapi.xml} AntiSamy policy configuration file
     * (or an alternate filename, specified via the "Validator.HtmlValidationConfigurationFile" property in your
     * {@ESAPI.properties} file. Implementors wishing to alter the AntiSamy policy configuration file should
     * reference the <a href="https://owasp.org/www-project-antisamy/">OWASP AntiSamy project</a> for ideas
     * on how to do HTML validation in a allow-list way, as this is an extremely difficult problem.
     * <p>
     * Calls {@link #getValidSafeHTML(String, String, int, boolean)}.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "LoginPage_UsernameField").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param maxLength
     *         The maximum {@code String} length allowed for {@code input}.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param errorList The error list to which any {@Code ValidationException} messages are added.
     *
     * @return A string representing the canonicalized and sanitized input that is safe for rendering in an HTML context.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidSafeHTML(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} matches the pattern for a valid credit card number.
     * <p>
     * Calls {@link #getValidCreditCard(String, String, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidCreditCard(String context, String input, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} matches the pattern for a valid credit card number,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidCreditCard(String, String, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a canonicalized and validated credit card number as a String.
     * <p>
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., PaymentPage_CreditCard).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid credit card number
     *
     * @throws ValidationException Input is invalid because it doesn't appear to be a valid credit card account number.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidCreditCard(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a canonicalized and validated credit card number as a String,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidCreditCard(String, String, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidCreditCard(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidDirectoryPath(String, String, File, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDirectoryPath(String, String, File, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a canonicalized and validated directory path as a String, provided that the input
     * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent.
     * <p>
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid directory path
     *
     * @throws ValidationException Input is invalid (e.g., the provided input is not a directory).
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidDirectoryPath(String context, String input, File parent, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a canonicalized and validated directory path as a String, provided that the input
     * maps to an existing directory that is an existing subdirectory (at any level) of the specified parent;
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDirectoryPath(String, String, File, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidDirectoryPath(String context, String input, File parent, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidFileName(String, String, List, boolean)}
     * with allowedExtensions set to the configured {@code ESAPI.securityConfiguration().getAllowedFileExtensions()}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @see ESAPI#securityConfiguration()
     * @see SecurityConfiguration#getAllowedFileExtensions()
     */
    boolean isValidFileName(String context, String input, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidFileName(String, String, List, boolean)}
     * with allowedExtensions set to the configured {@code ESAPI.securityConfiguration().getAllowedFileExtensions()}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @see ESAPI#securityConfiguration()
     * @see SecurityConfiguration#getAllowedFileExtensions()
     */
    boolean isValidFileName(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidFileName(String, String, List, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @see ESAPI#securityConfiguration()
     * @see SecurityConfiguration#getAllowedFileExtensions()
     */
    boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidFileName(String, String, List, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     *
     * @see ESAPI#securityConfiguration()
     * @see SecurityConfiguration#getAllowedFileExtensions()
     */
    boolean isValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a canonicalized and validated file name as a String.
     * Implementors should check for allowed file extensions here,
     * as well as allowed file name characters, as declared in "ESAPI.properties".
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param allowedExtensions
     *         List of file extensions which will be accepted.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A valid file name
     *
     * @throws ValidationException Input is invalid (e.g., {@code input} refers to a non-existant file, does not have a
     *         valid file extension as per {@code allowedExtensions}, does not match the canonicalized path,
     *         exceeds a maximum length of 255 characters, etc.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a canonicalized and validated file name as a String,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidFileName(String, String, List, boolean)},
     * the supplied {@code errorList} is used to capture ValidationExceptions.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidFileName(String context, String input, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidNumber(String, String, long, long, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidNumber(String, String, long, long, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a validated number as a double within the range of minValue to maxValue.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     *
     * @return A validated number as a double.
     *
     * @throws ValidationException Input is invalid; that is, not a number in the range
     *         of [{@code minValue}, {@code maxValue}].
     * @throws IntrusionException Input likely indicates an attack.
     */
    Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a validated number as a double within the range of
     * [{@code minValue}, {@code maxValue}]; any validation
     * exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidNumber(String, String, long, long, boolean)}.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "OrderPage_Quantity").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param errorList The error list to which any {@Code ValidationException} messages are added.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    Double getValidNumber(String context, String input, long minValue, long maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is a valid integer between {@code minValue} and {@code maxValue} inclusive.
     * <p>
     * Calls {@link #getValidInteger(String, String, int, int, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "OrderPage_Quantity").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is a valid integer between {@code minValue} and {@code maxValue} inclusive,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidInteger(String, String, int, int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., "OrderPage_Quantity").
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual user input data to validate.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param errorList The error list to which any {@Code ValidationException} messages are added.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a validated integer,
     * {@code input} is a valid integer if it is between {@code minValue} and {@code maxValue} inclusive.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., OrderPage_Quantity).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     *
     * @return A validated number as an integer.
     *
     * @throws ValidationException Input is not a valid integer in the range of [{@code minValue}, {@code maxValue}].
     * @throws IntrusionException Input likely indicates an attack.
     */
    Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a validated integer,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidInteger(String, String, int, int, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    Integer getValidInteger(String context, String input, int minValue, int maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidDouble(String, String, double, double, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDouble(String, String, double, double, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns a validated real number as a double.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     * @param minValue
     *         Lowest legal value for input.
     * @param maxValue
     *         Highest legal value for input.
     *
     * @return A validated real number as a double.
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a validated real number as a double,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidDouble(String, String, double, double, boolean)},
     * the supplied {@code errorList} is used to capture ValidationExceptions.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    Double getValidDouble(String context, String input, double minValue, double maxValue, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidFileContent(String, byte[], int, boolean)},
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidFileContent(String, byte[], int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns validated file content as a byte array.
     * This is a good place to check for max file size, allowed character sets, and do virus scans.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The actual input data to validate.
     * @param maxBytes
     *         The maximum number of bytes allowed in a legal file.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A byte array containing valid file content.
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns validated file content as a byte array,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidFileContent(String, byte[], int, boolean)},
     * the supplied {@code errorList} is used to capture ValidationExceptions.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    byte[] getValidFileContent(String context, byte[] input, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code filepath}, {@code filename}, and {@code content} of a file are valid.
     * <p>
     * Calls {@link #isValidFileName(String, String, boolean)},
     * {@link #isValidDirectoryPath(String, String, File, boolean)},
     * and {@link #isValidFileContent(String, byte[], int, boolean)},
     * and returns true if all three checks pass.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code filepath}, {@code filename}, and {@code content} of a file are valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #isValidFileName(String, String, boolean, ValidationErrorList)}
     * {@link #isValidDirectoryPath(String, String, File, boolean, ValidationErrorList)}
     * and {@link #isValidFileContent(String, byte[], int, boolean, ValidationErrorList)},
     * and returns true if all three checks pass.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Validates the {@code filepath}, {@code filename}, and {@code content} of a file.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param filepath
     *         The file path of the uploaded file.
     * @param filename
     *         The filename of the uploaded file
     * @param content
     *         A byte array containing the content of the uploaded file.
     * @param maxBytes
     *         The max number of bytes allowed for a legal file upload.
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Validates the {@code filepath}, {@code filename}, and {@code content} of a file,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #assertValidFileUpload(String, String, String, File, byte[], int, List, boolean)},
     * the supplied {@code errorList} is used to capture ValidationExceptions.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    void assertValidFileUpload(String context, String filepath, String filename, File parent, byte[] content, int maxBytes, List<String> allowedExtensions, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidListItem(String, String, List)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidListItem(String context, String input, List<String> list) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidListItem(String, String, List)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns the list item that exactly matches the canonicalized input.
     * Invalid or non-matching input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         The value to search 'list' for.
     * @param list
     *         The list to search for 'input'.
     *
     * @return The list item that exactly matches the canonicalized input.
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidListItem(String context, String input, List<String> list) throws ValidationException, IntrusionException;

    /**
     * Returns the list item that exactly matches the canonicalized input,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidListItem(String, String, List)}
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidListItem(String context, String input, List<String> list, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if only required and optional parameters are in the request.
     * <p>
     * Calls {@link #assertValidHTTPRequestParameterSet(String, HttpServletRequest, Set, Set)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws IntrusionException;

    /**
     * Returns true if only required and optional parameters are in the request,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #assertValidHTTPRequestParameterSet(String, HttpServletRequest, Set, Set)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Validates that the parameters in the current request contain all required parameters
     * and only optional ones in addition.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField). This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param required
     *         parameters that are required to be in HTTP request
     * @param optional
     *         additional parameters that may be in HTTP request
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional) throws ValidationException, IntrusionException;

    /**
     * Validates that the parameters in the current request contain all required parameters
     * and only optional ones in addition,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #assertValidHTTPRequestParameterSet(String, HttpServletRequest, Set, Set)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    void assertValidHTTPRequestParameterSet(String context, HttpServletRequest request, Set<String> required, Set<String> optional, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidPrintable(String, char[], int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidPrintable(String, char[], int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns canonicalized and validated printable characters as a byte array.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         data to be returned as valid and printable
     * @param maxLength
     *         Maximum number of bytes stored in 'input'
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return a byte array containing only printable characters, made up of data from 'input'
     *
     * @throws ValidationException Input is invalid.
     */
    char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull) throws ValidationException;

    /**
     * Returns canonicalized and validated printable characters as a byte array,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidPrintable(String, char[], int, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    char[] getValidPrintable(String context, char[] input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidPrintable(String, String, int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidPrintable(String, String, int, boolean)}
     * and returns true if no exceptions are thrown.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    boolean isValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns canonicalized and validated printable characters as a String.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         data to be returned as valid and printable
     * @param maxLength
     *         Maximum number of bytes stored in 'input' after canonicalization
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return a String containing only printable characters, made up of data from 'input'
     *
     * @throws ValidationException Input is invalid.
     */
    String getValidPrintable(String context, String input, int maxLength, boolean allowNull) throws ValidationException;

    /**
     * Returns canonicalized and validated printable characters as a String,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidPrintable(String, String, int, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidPrintable(String context, String input, int maxLength, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Returns true if {@code input} is valid.
     * <p>
     * Calls {@link #getValidRedirectLocation(String, String, boolean)}
     * and returns true if no exceptions are thrown.
     */
    boolean isValidRedirectLocation(String context, String input, boolean allowNull);

    /**
     * Returns true if {@code input} is valid,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidRedirectLocation(String, String, boolean)}
     * and returns true if no exceptions are thrown.
     */
    boolean isValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errorList);

    /**
     * Returns a canonicalized and validated redirect location as a String.
     * Invalid input will generate a descriptive ValidationException,
     * and input that is clearly an attack will generate a descriptive IntrusionException.
     *
     * @param context
     *         A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *         This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *         redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
     * @param allowNull
     *         If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *         If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return A canonicalized and validated redirect location, as defined in "ESAPI.properties"
     *
     * @throws ValidationException Input is invalid.
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidRedirectLocation(String context, String input, boolean allowNull) throws ValidationException, IntrusionException;

    /**
     * Returns a canonicalized and validated redirect location as a String,
     * any validation exceptions are added to the supplied {@code errorList}.
     * <p>
     * Calls {@link #getValidRedirectLocation(String, String, boolean)}.
     *
     * @throws IntrusionException Input likely indicates an attack.
     */
    String getValidRedirectLocation(String context, String input, boolean allowNull, ValidationErrorList errorList) throws IntrusionException;

    /**
     * Reads from an input stream until end-of-line or a maximum number of
     * characters. This method protects against the inherent denial of service
     * attack in reading until the end of a line. If an attacker doesn't ever
     * send a newline character, then a normal input stream reader will read
     * until all memory is exhausted and the platform throws an OutOfMemoryError
     * and probably terminates.
     *
     * @param inputStream
     *         The InputStream from which to read data
     * @param maxLength
     *         Maximum characters allowed to be read in per line
     *
     * @return a String containing the current line of inputStream
     *
     * @throws ValidationException Input is invalid.
     */
    String safeReadLine(InputStream inputStream, int maxLength) throws ValidationException;

    /**
     * Parses and ensures that the URI in question is a valid RFC-3986 URI.  This simplifies
     * the kind of regex required for subsequent validation to mitigate regex-based DoS attacks.
     *
     * @see <a href="https://www.ietf.org/rfc/rfc3986.txt">RFC-3986.</a>
     *
     * @param context
     *          A descriptive name of the parameter that you are validating (e.g., LoginPage_UsernameField).
     *          This value is used by any logging or error handling that is done with respect to the value passed in.
     * @param input
     *          redirect location to be returned as valid, according to encoding rules set in "ESAPI.properties"
     * @param allowNull
     *          If {@code allowNull} is true then an input that is NULL or an empty string will be legal.
     *          If {@code allowNull} is false then NULL or an empty String will throw a ValidationException.
     *
     * @return True if the URI is valid
     */
    boolean isValidURI(String context, String input, boolean allowNull);

    /**
     * Will return a {@code URI} object that will represent a fully parsed and legal URI
     * as specified in RFC-3986.
     *
     * @param input String
     * @return URI object representing a parsed URI, or {@code null} if the URI was non-compliant in some way.
     */
    URI getRfcCompliantURI(String input);

}
