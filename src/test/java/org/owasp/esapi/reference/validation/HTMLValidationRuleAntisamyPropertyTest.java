/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2019 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author kevin.w.wall@gmail.com
 * @since 2019
 */
package org.owasp.esapi.reference.validation;

import org.junit.Test;
import org.owasp.validator.html.PolicyException;

/**
 * Isolate scope test to assert the behavior of the HTMLValidationRule
 * when schema validation is disabled in the Antisamy Project.
 */
public class HTMLValidationRuleAntisamyPropertyTest {
    /** The intentionally non-compliant AntiSamy policy file. We don't intend to
     * actually <i>use</i> it for anything.
     */
    private static final String INVALID_ANTISAMY_POLICY_FILE = "antisamy-InvalidPolicy.xml";

    @Test( expected = PolicyException.class )
    public void checkAntisamySystemPropertyWorksAsAdvertised() throws Exception {
        HTMLValidationRule.loadAntisamyPolicy(INVALID_ANTISAMY_POLICY_FILE);
    }

}
