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



import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Arrays;
import java.util.List;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Logger;
import org.owasp.esapi.SecurityConfiguration;
import org.owasp.esapi.StringUtilities;
import org.owasp.esapi.errors.ConfigurationException;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultSecurityConfiguration.DefaultSearchPath;
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
	private static final String ANTISAMYPOLICY_FILENAME = "antisamy-esapi.xml";

	//TESTING -- Mock Classloaders, verify that the classloader is called as desired with the searchpath and filename concat
	// Verify that when no match is found, null is returned
	// Verify that when match is found, remaining classloaders are not invoked and expected InputStream is returned.
	/*package */ static InputStream getResourceStreamFromClassLoader(String contextDescription, ClassLoader classLoader, String fileName, List<String> searchPaths) {
	    InputStream result = null;
	    
	    for (String searchPath: searchPaths) {
	        result = classLoader.getResourceAsStream(searchPath + fileName);
	        
	        if (result != null) {
	            LOGGER.info(Logger.EVENT_SUCCESS, "SUCCESSFULLY LOADED " + fileName + " via the CLASSPATH from '" + 
	                    searchPath + "' using " + contextDescription + "!");
	                break; 
	        }
	    }
	    
	    return result;
	}
	
	//TESTING
	// Harder to test... Use Junit to place files in each of the DefaultSearchPathLocations and verify that the file can be found.
	// Not sure how to test that the classpaths are iterated.
	/*package */ static InputStream getResourceStreamFromClasspath(String fileName) {
	    LOGGER.info(Logger.EVENT_FAILURE, "Loading " + fileName + " from classpaths");
		
	    InputStream resourceStream = null;
		
		List<String> orderedSearchPaths = Arrays.asList(DefaultSearchPath.ROOT.value(), 
		        DefaultSearchPath.RESOURCE_DIRECTORY.value(),
		        DefaultSearchPath.DOT_ESAPI.value(),
		        DefaultSearchPath.ESAPI.value(),
		        DefaultSearchPath.RESOURCES.value(),
		        DefaultSearchPath.SRC_MAIN_RESOURCES.value());
		
		resourceStream = getResourceStreamFromClassLoader("current thread context class loader", Thread.currentThread().getContextClassLoader(), fileName, orderedSearchPaths);
		 
		//I'm lazy. Using ternary for shorthand "if null then do next thing"  Harder to read, sorry
		resourceStream = resourceStream != null ? resourceStream : getResourceStreamFromClassLoader("system class loader", ClassLoader.getSystemClassLoader(), fileName, orderedSearchPaths);
		resourceStream = resourceStream != null ? resourceStream : getResourceStreamFromClassLoader("class loader for DefaultSecurityConfiguration class", ESAPI.securityConfiguration().getClass().getClassLoader(), fileName, orderedSearchPaths);
		
		return resourceStream;
	}
	
	//TESTING
	// Mock SecurityConfiguration - Return file check (true) - return resourceStream - expect Policy object
	// Mock SecurityConfiguration - Return file check (false)  - use junit to place file in any of the DefaultSearchPathLocations - verify Policy Object
	// Mock SecurityConfiguration - return file check (true) - throw IOException on resource stream - Verify IOException
	// Mock SecurityConfiguration - return file Check (true) - use Junit to place a BAD FILE - verify PolicyException
	//  HOW TO TEST NULL RETURN.....
	/*package */ static Policy loadAntisamyPolicy(String antisamyPolicyFilename) throws IOException, PolicyException {
	    InputStream resourceStream = null;
	    SecurityConfiguration secCfg = ESAPI.securityConfiguration();
	    
	    //Rather than catching the IOException from the resource stream, let's ask if the file exists to give this a best-case resolution.
	    //This helps with the IOException handling too.  If the file is there and we get an IOException from the SecurityConfiguration, then the file is there and something else is wrong (FAIL -- don't try the other path)
	    File file = secCfg.getResourceFile(antisamyPolicyFilename);
    
        resourceStream = file == null ? getResourceStreamFromClasspath(antisamyPolicyFilename) : secCfg.getResourceStream(antisamyPolicyFilename);
        resourceStream = resourceStream == null ? null : toByteArrayStream(resourceStream);
        return resourceStream == null ? null : Policy.getInstance(resourceStream);
	}
	
   //FIXME:  Remove this post antisamy v. 1.6.1 pending fix of issue 75
    private static InputStream toByteArrayStream(InputStream in) throws IOException {
        byte[] byteArray;
        try (Reader reader = new InputStreamReader(in)) {
            char[] charArray = new char[8 * 1024];
            StringBuilder builder = new StringBuilder();
            int numCharsRead;
            while ((numCharsRead = reader.read(charArray, 0, charArray.length)) != -1) {
                builder.append(charArray, 0, numCharsRead);
            }
            byteArray = builder.toString().getBytes();
        }
                
        return new ByteArrayInputStream(byteArray);        
    }
	
	//TESTING
	// Mock SecurityConfiguration - return a valid string on property request - verify String is returned from call
	// Mock SecurityConfiguration -- throw ConfigurationException on property request -- Verify Default Filename is returned from call
	/*package */ static String resolveAntisamyFilename() {
	    String antisamyPolicyFilename = ANTISAMYPOLICY_FILENAME;
        try {
            antisamyPolicyFilename = ESAPI.securityConfiguration().getStringProp(
                    // Future: This will be moved to a new PropNames class
                org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE );
        } catch (ConfigurationException cex) {
            
            LOGGER.info(Logger.EVENT_FAILURE, "ESAPI property " + 
                           org.owasp.esapi.reference.DefaultSecurityConfiguration.VALIDATOR_HTML_VALIDATION_CONFIGURATION_FILE +
                           " not set, using default value: " + ANTISAMYPOLICY_FILENAME);
        }
        return antisamyPolicyFilename;
	}
	
	//TESTING
	// Mock SecurityConfiguration - return file check (true) - throw IOException on resource stream - Verify ConfigurationException from IOException
    // Mock SecurityConfiguration - return file Check (true) - use Junit to place a BAD FILE - verify ConfigurationException from PolicyException
	// Force NULL return from loadAntisamyPolicy call -- Verify ConfigurationException from null value
	/*package */ static void configureInstance() {
	    String antisamyPolicyFilename = resolveAntisamyFilename();

        try {
            antiSamyPolicy = loadAntisamyPolicy(antisamyPolicyFilename);
        } catch (IOException ioe) {
            //Thrown if file is found by SecurityConfiguration, but a stream cannot be generated.
            throw new ConfigurationException("Failed to load file from SecurityConfiguration context: " + antisamyPolicyFilename, ioe);
        } catch (PolicyException e) {
            //Thrown if the resource stream was created, but the contents of the file are not compatible with antisamy expectations.
            throw new ConfigurationException("Couldn't parse " + antisamyPolicyFilename, e);
        }
        
        if (antiSamyPolicy == null) {
            throw new ConfigurationException("Couldn't find " + antisamyPolicyFilename);
        }

	}
	
	//TESTING
	// None.
	static {		
	    configureInstance();
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

