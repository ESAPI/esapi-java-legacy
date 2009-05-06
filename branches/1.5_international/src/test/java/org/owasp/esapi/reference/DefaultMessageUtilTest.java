/**
 * 
 */
package org.owasp.esapi.reference;

import java.util.Locale;

import org.owasp.esapi.ESAPI;

import junit.framework.TestCase;


/**
 * @author Pawan Singh
 *
 */
public class DefaultMessageUtilTest extends TestCase {
    /**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void setUp() throws Exception {
		// none
	}

    /**
     * {@inheritDoc}
     *
     * @throws Exception
     */
	protected void tearDown() throws Exception {
		// none
	}
	
	public void testGetMessage() {
		ESAPI.authenticator().getCurrentUser().setLocale(new Locale("en", "US"));
		System.out.println(ESAPI.messageUtil().getMessage("Error.creating.randomizer",null));
		String[] args = {"one","two","three"};
		System.out.println(ESAPI.messageUtil().getMessage("This.is.test.message",args));
		ESAPI.authenticator().getCurrentUser().setLocale(new Locale("zhs", "CN"));
		System.out.println(ESAPI.messageUtil().getMessage("Back_error_popup.tpl.13",null));
		
		
	}
}