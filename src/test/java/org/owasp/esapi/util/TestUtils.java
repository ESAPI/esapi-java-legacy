package org.owasp.esapi.util;

public class TestUtils {

	public static String generateStringOfLength(int length) {
	    assert length >= 0 : "length must be >= 0";
	    StringBuilder longString = new StringBuilder(length);
	    for (int i = 0; i < length; i++) {
	        longString.append("a");
	    }
	    return longString.toString();
	}

}
