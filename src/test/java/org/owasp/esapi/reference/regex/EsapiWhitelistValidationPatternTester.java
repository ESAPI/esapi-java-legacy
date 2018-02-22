/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2008-2018 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 */

package org.owasp.esapi.reference.regex;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.Assume;
import org.junit.runners.Parameterized.Parameters;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;

/**
 * Extension of the AbstractPatternTest which focuses on asserting that the default whitelist regex values applied in
 * the validation process are performing the intended function in the environment.
 * <br/>
 * If the regex values in this test are found to not match the running environment configurations, then the tests will
 * be skipped.
 *
 * @author Jeremiah
 * @since Jan 20, 2018
 */
public class EsapiWhitelistValidationPatternTester extends AbstractPatternTest {
    // See ESAPI.properties
    private static final String HTTP_QUERY_STRING_PROP_NAME = "HTTPQueryString";
    private static final String HTTP_QUERY_STRING_REGEX = "^([a-zA-Z0-9_\\-]{1,32}=[\\p{L}\\p{N}.\\-/+=_ !$*?@%]*&?)*$";

    private static final String CONFIGURATION_PATTERN_MISMATCH_MESSAGE = "The regular expression specified does not match the configuration settings.\n"
        + "If the value was changed from the ESAPI default, it is recommended to copy "
        + "this class into your project, update the regex being tested, and update all "
        + "associated input expectations for your unique environment.";

    @Parameters(name = "{0}-{1}")
    public static Collection<Object[]> createDefaultPatternTests() {
        Collection<Object[]> parameters = new ArrayList<>();

        for (PatternTestTuple tuple : buildHttpQueryStringTests()) {
            parameters.add(new Object[] { HTTP_QUERY_STRING_PROP_NAME, tuple });
        }

        return parameters;
    }

    private static Collection<PatternTestTuple> buildHttpQueryStringTests() {
        Collection<PatternTestTuple> httpQueryStringTests = new ArrayList<>();

        // MATCHING CASES
        PatternTestTuple tuple = newHttpQueryStringTuple("Default Case", "b", true);
        httpQueryStringTests.add(tuple);
        tuple = newHttpQueryStringTuple("Percent Encoded Value", "%62", true);
        httpQueryStringTests.add(tuple);
        tuple = newHttpQueryStringTuple("Percent Encoded Null Character", "%00", true);
        httpQueryStringTests.add(tuple);
        tuple = newHttpQueryStringTuple("Double Equals", "=", true);
        httpQueryStringTests.add(tuple);

        // NON-MATCHING CASES
        tuple = newHttpQueryStringTuple("Ampersand In Value", "&b", false);
        httpQueryStringTests.add(tuple);
        tuple = newHttpQueryStringTuple("Null Character", "" + Character.MIN_VALUE, false);
        httpQueryStringTests.add(tuple);
        tuple = newHttpQueryStringTuple("Encoded Null Character", "\u0000", false);
        httpQueryStringTests.add(tuple);

        return httpQueryStringTests;
    }

    private static PatternTestTuple newHttpQueryStringTuple(String description, String value, boolean shouldPass) {
        PatternTestTuple tuple = new PatternTestTuple();
        tuple.input = "a=" + value;
        tuple.shouldMatch = shouldPass;
        tuple.regex = HTTP_QUERY_STRING_REGEX;
        tuple.description = description;
        return tuple;
    }

    public EsapiWhitelistValidationPatternTester(String property, PatternTestTuple tuple) {
        super(tuple);
        /*
         * This next block causes the case to be skipped programatically if the regex being tested
         * is different than the one being loaded at runtime.
         * This is being done to prevent a false sense of security.
         * If the configurations are changed to meet additional environmental concerns, the intent of this test should
         * be copied into that environment and tested there to assert the additional expectations or changes in desired
         * behavior.
         */
        DefaultSecurityConfiguration configuration = new DefaultSecurityConfiguration();
        Assume.assumeTrue(CONFIGURATION_PATTERN_MISMATCH_MESSAGE, configuration.getValidationPattern(property)
            .toString().equals(tuple.regex));
    }

}
