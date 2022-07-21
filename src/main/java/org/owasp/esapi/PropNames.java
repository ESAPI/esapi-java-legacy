// TODO: Discuss: Should the name of this be PropConstants or PropertConstants
//                since there are some property values included here? I don't
//                really like that as much as PropNames, but I could live with
//                it.
/*
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * https://owasp.org/www-project-enterprise-security-api/.
 *
 * Copyright (c) 2022 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 */
package org.owasp.esapi;


/**
 * This non-constructable class of public constants defines all the property names used in {@code ESAPI.properties} as
 * well as some of the default property values for some of those properties. This class is not intended
 * to be extended or instantiated. Technically, an interface would have worked here, but we
 * also wanted to be able to prevent 'implements PropNames', which really does not make much
 * sense since no specific behavior is promised here. Another alternative would have
 * been to place all of these in the {@code org.owasp.esapi.SecurityConfiguration} interface,
 * but that interface is already overly bloated. Hence this was decided as a compromise.
 * </p><p>
 * Note that the constants herein were originally all defined within
 * {@code org.owasp.esapi.reference.DefaultSecurityConfiguration}, but those
 * values are now marked deprecated and they are candidates for removal 2 years
 * from the date of this release.
 * </p><p>
 * Mostly this is intended to prevent having to hard-code property names all
 * over the place in implementation-level classes (e.g.,
 * {@code org.owasp.esapi.reference.DefaultSecurityConfiguration}).
 * It is suggested that this file be used as a 'static import';
 * e.g.,
 * <pre>
 *      import static org.owasp.esapi.PropNames.*;                      // Import all properties, en masse
 * or
 *      import static org.owasp.esapi.PropNames.SomeSpecificPropName;   // Import specific property name
 * </pre>
 * This can be extremely useful when used with methods such as
 * {@code SecurityConfiguration.getIntProp(String propName)},
 * {@code SecurityConfiguration.getBooleanProp(String propName)},
 * {@code SecurityConfiguration.getStringProp(String propName)}, etc.
 *
 * @author Kevin W. Wall (kevin.w.wall .at. gmail.com)
 * @since 2.4.1.0
 * @see org.owasp.esapi.reference.DefaultSecurityConfiguration
 */

public final class PropNames {

    public static final String REMEMBER_TOKEN_DURATION                                                          = "Authenticator.RememberTokenDuration";
    public static final String IDLE_TIMEOUT_DURATION                                                            = "Authenticator.IdleTimeoutDuration";
    public static final String ABSOLUTE_TIMEOUT_DURATION                                                        = "Authenticator.AbsoluteTimeoutDuration";
    public static final String ALLOWED_LOGIN_ATTEMPTS                                                           = "Authenticator.AllowedLoginAttempts";
    public static final String USERNAME_PARAMETER_NAME                                                          = "Authenticator.UsernameParameterName";
    public static final String PASSWORD_PARAMETER_NAME                                                          = "Authenticator.PasswordParameterName";
    public static final String MAX_OLD_PASSWORD_HASHES                                                          = "Authenticator.MaxOldPasswordHashes";

    public static final String ALLOW_MULTIPLE_ENCODING                                                          = "Encoder.AllowMultipleEncoding";
    public static final String ALLOW_MIXED_ENCODING                                                             = "Encoder.AllowMixedEncoding";
    public static final String CANONICALIZATION_CODECS                                                          = "Encoder.DefaultCodecList";

    public static final String DISABLE_INTRUSION_DETECTION                                                      = "IntrusionDetector.Disable";

    public static final String MASTER_KEY                                                                       = "Encryptor.MasterKey";
    public static final String MASTER_SALT                                                                      = "Encryptor.MasterSalt";
    public static final String KEY_LENGTH                                                                       = "Encryptor.EncryptionKeyLength";
    public static final String ENCRYPTION_ALGORITHM                                                             = "Encryptor.EncryptionAlgorithm";
    public static final String HASH_ALGORITHM                                                                   = "Encryptor.HashAlgorithm";
    public static final String HASH_ITERATIONS                                                                  = "Encryptor.HashIterations";
    public static final String CHARACTER_ENCODING                                                               = "Encryptor.CharacterEncoding";
    public static final String RANDOM_ALGORITHM                                                                 = "Encryptor.RandomAlgorithm";
    public static final String DIGITAL_SIGNATURE_ALGORITHM                                                      = "Encryptor.DigitalSignatureAlgorithm";
    public static final String DIGITAL_SIGNATURE_KEY_LENGTH                                                     = "Encryptor.DigitalSignatureKeyLength";
    public static final String PREFERRED_JCE_PROVIDER                                                           = "Encryptor.PreferredJCEProvider";
    public static final String CIPHER_TRANSFORMATION_IMPLEMENTATION                                             = "Encryptor.CipherTransformation";
    public static final String CIPHERTEXT_USE_MAC                                                               = "Encryptor.CipherText.useMAC";
    public static final String PLAINTEXT_OVERWRITE                                                              = "Encryptor.PlainText.overwrite";
    public static final String IV_TYPE                                                                          = "Encryptor.ChooseIVMethod";   // Will be removed in future release.
    public static final String COMBINED_CIPHER_MODES                                                            = "Encryptor.cipher_modes.combined_modes";
    public static final String ADDITIONAL_ALLOWED_CIPHER_MODES                                                  = "Encryptor.cipher_modes.additional_allowed";
    public static final String KDF_PRF_ALG                                                                      = "Encryptor.KDF.PRF";
    public static final String PRINT_PROPERTIES_WHEN_LOADED                                                     = "ESAPI.printProperties";

    public static final String WORKING_DIRECTORY                                                                = "Executor.WorkingDirectory";
    public static final String APPROVED_EXECUTABLES                                                             = "Executor.ApprovedExecutables";

    public static final String FORCE_HTTPONLYSESSION                                                            = "HttpUtilities.ForceHttpOnlySession";
    public static final String FORCE_SECURESESSION                                                              = "HttpUtilities.SecureSession";
    public static final String FORCE_HTTPONLYCOOKIES                                                            = "HttpUtilities.ForceHttpOnlyCookies";
    public static final String FORCE_SECURECOOKIES                                                              = "HttpUtilities.ForceSecureCookies";
    public static final String MAX_HTTP_HEADER_SIZE                                                             = "HttpUtilities.MaxHeaderSize";
    public static final String UPLOAD_DIRECTORY                                                                 = "HttpUtilities.UploadDir";
    public static final String UPLOAD_TEMP_DIRECTORY                                                            = "HttpUtilities.UploadTempDir";
    public static final String APPROVED_UPLOAD_EXTENSIONS                                                       = "HttpUtilities.ApprovedUploadExtensions";
    public static final String MAX_UPLOAD_FILE_BYTES                                                            = "HttpUtilities.MaxUploadFileBytes";
    public static final String RESPONSE_CONTENT_TYPE                                                            = "HttpUtilities.ResponseContentType";
    public static final String HTTP_SESSION_ID_NAME                                                             = "HttpUtilities.HttpSessionIdName";

    public static final String APPLICATION_NAME                                                                 = "Logger.ApplicationName";
    public static final String LOG_USER_INFO                                                                    = "Logger.UserInfo";
    public static final String LOG_CLIENT_INFO                                                                  = "Logger.ClientInfo";
    public static final String LOG_ENCODING_REQUIRED                                                            = "Logger.LogEncodingRequired";
    public static final String LOG_APPLICATION_NAME                                                             = "Logger.LogApplicationName";
    public static final String LOG_SERVER_IP                                                                    = "Logger.LogServerIP";

    public static final String VALIDATION_PROPERTIES                                                            = "Validator.ConfigurationFile";
    public static final String VALIDATION_PROPERTIES_MULTIVALUED                                                = "Validator.ConfigurationFile.MultiValued";
    public static final String ACCEPT_LENIENT_DATES                                                             = "Validator.AcceptLenientDates";
    public static final String VALIDATOR_HTML_VALIDATION_ACTION                                                 = "Validator.HtmlValidationAction";
    public static final String VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE                                     = "Validator.HtmlValidationConfigurationFile";

    /**
     * Special {@code java.lang.System} property that, if set to {@code true}, will
     * disable logging from {@code DefaultSecurityConfiguration.logToStdout()}
     * methods, which is called from various {@code logSpecial()} methods.
     *
     * @see org.owasp.esapi.reference.DefaultSecurityConfiguration#logToStdout(String msg, Throwable t)
     */
    public static final String DISCARD_LOGSPECIAL                                                               = "org.owasp.esapi.logSpecial.discard";

    /*
     * Implementation Keys
     */
    public static final String LOG_IMPLEMENTATION                                                               = "ESAPI.Logger";
    public static final String AUTHENTICATION_IMPLEMENTATION                                                    = "ESAPI.Authenticator";
    public static final String ENCODER_IMPLEMENTATION                                                           = "ESAPI.Encoder";
    public static final String ACCESS_CONTROL_IMPLEMENTATION                                                    = "ESAPI.AccessControl";
    public static final String ENCRYPTION_IMPLEMENTATION                                                        = "ESAPI.Encryptor";
    public static final String INTRUSION_DETECTION_IMPLEMENTATION                                               = "ESAPI.IntrusionDetector";
    public static final String RANDOMIZER_IMPLEMENTATION                                                        = "ESAPI.Randomizer";
    public static final String EXECUTOR_IMPLEMENTATION                                                          = "ESAPI.Executor";
    public static final String VALIDATOR_IMPLEMENTATION                                                         = "ESAPI.Validator";
    public static final String HTTP_UTILITIES_IMPLEMENTATION                                                    = "ESAPI.HTTPUtilities";


    //////////////////////////////////////////////////////////////////////////////
    //                                                                          //
    // These are not really property names, but the shouldn't really be in an   //
    // implementation class that we want to only deal with via the              //
    // SecurityConfiguration interface.                                         //
    //                                                                          //
    //////////////////////////////////////////////////////////////////////////////


    /*
     * These are default implementation classes.
     */
    public static final String DEFAULT_LOG_IMPLEMENTATION                                                       = "org.owasp.esapi.logging.java.JavaLogFactory";
    public static final String DEFAULT_AUTHENTICATION_IMPLEMENTATION                                            = "org.owasp.esapi.reference.FileBasedAuthenticator";
    public static final String DEFAULT_ENCODER_IMPLEMENTATION                                                   = "org.owasp.esapi.reference.DefaultEncoder";
    public static final String DEFAULT_ACCESS_CONTROL_IMPLEMENTATION                                            = "org.owasp.esapi.reference.DefaultAccessController";
    public static final String DEFAULT_ENCRYPTION_IMPLEMENTATION                                                = "org.owasp.esapi.reference.crypto.JavaEncryptor";
    public static final String DEFAULT_INTRUSION_DETECTION_IMPLEMENTATION                                       = "org.owasp.esapi.reference.DefaultIntrusionDetector";
    public static final String DEFAULT_RANDOMIZER_IMPLEMENTATION                                                = "org.owasp.esapi.reference.DefaultRandomizer";
    public static final String DEFAULT_EXECUTOR_IMPLEMENTATION                                                  = "org.owasp.esapi.reference.DefaultExecutor";
    public static final String DEFAULT_HTTP_UTILITIES_IMPLEMENTATION                                            = "org.owasp.esapi.reference.DefaultHTTPUtilities";
    public static final String DEFAULT_VALIDATOR_IMPLEMENTATION                                                 = "org.owasp.esapi.reference.DefaultValidator";

    /** The name of the ESAPI property file */
    public static final String DEFAULT_RESOURCE_FILE                                                            = "ESAPI.properties";

    //
    // Private CTOR to prevent creation of PropName objects. We wouldn't need
    // this if this were an interface, nor would we need the explict 'public static final'.
    //
    private PropNames() {
        throw new AssertionError("Thought you'd cheat using reflection or JNI, huh? :)");
    }


    /** Enum used with the search paths used to locate an
     * {@code ESAPI.properties} and/or a {@code validation.properties}
     * file.
     */
    public enum DefaultSearchPath {

        RESOURCE_DIRECTORY("resourceDirectory/"),
        SRC_MAIN_RESOURCES("src/main/resources/"),
        ROOT(""),
        DOT_ESAPI(".esapi/"),
        ESAPI("esapi/"),
        RESOURCES("resources/");

        private final String path;

        private DefaultSearchPath(String s){
            this.path = s;
        }

        public String value(){
            return path;
        }
    }
}
