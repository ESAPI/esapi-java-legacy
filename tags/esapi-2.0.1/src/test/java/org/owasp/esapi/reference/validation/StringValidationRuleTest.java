package org.owasp.esapi.reference.validation;

import junit.framework.Assert;

import org.junit.Test;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;

public class StringValidationRuleTest {

	@Test
	public void testWhitelistPattern() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("Alphabetic");
		
		Assert.assertEquals("Magnum44", validationRule.getValid("", "Magnum44"));
		validationRule.addWhitelistPattern("^[a-zA-Z]*");
		try {
			validationRule.getValid("", "Magnum44");
			Assert.fail("Expected Exception not thrown");
		}
		catch (ValidationException ve) {
			Assert.assertNotNull(ve.getMessage());
		}
		Assert.assertEquals("MagnumPI", validationRule.getValid("", "MagnumPI"));
		
	}
	
	@Test
	public void testWhitelistPattern_Invalid() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("");
		
		//null white list patterns throw IllegalArgumentException
		try {
			String pattern = null;
			validationRule.addWhitelistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
		
		try {
			java.util.regex.Pattern pattern = null;
			validationRule.addWhitelistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
		
		//invalid white list patterns throw PatternSyntaxException
		try {
			String pattern = "_][0}[";
			validationRule.addWhitelistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
	}
	
	@Test
	public void testWhitelist() {
		StringValidationRule validationRule = new StringValidationRule("");
		
		char[] whitelistArray = new char[] {'a', 'b', 'c'};
		Assert.assertEquals("abc", validationRule.whitelist("12345abcdef", whitelistArray));
	}
	
	@Test
	public void testBlacklistPattern() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("NoAngleBrackets");
		
		Assert.assertEquals("beg <script> end", validationRule.getValid("", "beg <script> end"));
		validationRule.addBlacklistPattern("^.*(<|>).*");
		try {
			validationRule.getValid("", "beg <script> end");
			Assert.fail("Expected Exception not thrown");
		}
		catch (ValidationException ve) {
			Assert.assertNotNull(ve.getMessage());
		}
		Assert.assertEquals("beg script end", validationRule.getValid("", "beg script end"));
	}
	
	@Test
	public void testBlacklistPattern_Invalid() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("");
		
		//null black list patterns throw IllegalArgumentException
		try {
			String pattern = null;
			validationRule.addBlacklistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
		
		try {
			java.util.regex.Pattern pattern = null;
			validationRule.addBlacklistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
		
		//invalid black list patterns throw PatternSyntaxException
		try {
			String pattern = "_][0}[";
			validationRule.addBlacklistPattern(pattern);
			Assert.fail("Expected Exception not thrown");
		}
		catch (IllegalArgumentException ie) {
			Assert.assertNotNull(ie.getMessage());
		}
	}	
	
	@Test
	public void testCheckLengths() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("Max12_Min2");
		validationRule.setMinimumLength(2);
		validationRule.setMaximumLength(12);
		
		Assert.assertTrue(validationRule.isValid("", "12"));
		Assert.assertTrue(validationRule.isValid("", "123456"));
		Assert.assertTrue(validationRule.isValid("", "ABCDEFGHIJKL"));
		
		Assert.assertFalse(validationRule.isValid("", "1"));
		Assert.assertFalse(validationRule.isValid("", "ABCDEFGHIJKLM"));
		
		ValidationErrorList errorList = new ValidationErrorList();
		Assert.assertEquals("1234567890", validationRule.getValid("", "1234567890", errorList));
		Assert.assertEquals(0, errorList.size());
		Assert.assertEquals(null, validationRule.getValid("", "123456789012345", errorList));
		Assert.assertEquals(1, errorList.size());
	}
	
	@Test
	public void testAllowNull() throws ValidationException {
		
		StringValidationRule validationRule = new StringValidationRule("");
		
		Assert.assertFalse(validationRule.isAllowNull());
		Assert.assertFalse(validationRule.isValid("", null));
		
		validationRule.setAllowNull(true);
		Assert.assertTrue(validationRule.isAllowNull());
		Assert.assertTrue(validationRule.isValid("", null));
	}
	
}
