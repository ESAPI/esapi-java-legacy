/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2009 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Arshan Dabirsiaghi <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2009
 */
package org.owasp.esapi.waf.rules;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;

import org.owasp.esapi.waf.configuration.AppGuardianConfiguration;

/**
 * This is a small utility class for use by Rule subclasses.
 * @author Arshan Dabirsiaghi
 *
 */
public class RuleUtil {

	public static boolean isInList(Map m, String s) {

		Iterator it = m.keySet().iterator();

		while( it.hasNext() ) {
			String key = (String)it.next();
			if ( key.equals(s) ) {
				return true;
			}
		}

		return false;
	}

	public static boolean isInList(Collection c, String s) {

		Iterator it = c.iterator();

		while(it.hasNext()) {

			Object o = it.next();

			if ( o instanceof String ) {

				if ( s.equals((String)o)) {
					return true;
				}

			} else if ( o instanceof Integer ) {

				try {
					if ( Integer.parseInt(s) == ((Integer)o).intValue() ) {
						return true;
					}
				} catch (Exception e) {}

			} else if ( o instanceof Long ) {

				try {
					if ( Long.parseLong(s) == ((Long)o).longValue() ) {
						return true;
					}
				} catch (Exception e) {}

			} else if ( o instanceof Double ) {

				try {
					if ( Double.parseDouble(s) == ((Double)o).doubleValue() ) {
						return true;
					}
				} catch (Exception e) {}
			}

		}

		return false;
	}

	/*
	 * Enumeration
	 */
	public static boolean isInList(Enumeration en, String s) {

		for(; en.hasMoreElements();) {

			Object o = en.nextElement();

			if ( o instanceof String ) {

				if ( s.equals((String)o)) {
					return true;
				}

			} else if ( o instanceof Integer ) {

				try {
					if ( Integer.parseInt(s) == ((Integer)o).intValue() ) {
						return true;
					}
				} catch (Exception e) {}

			} else if ( o instanceof Long ) {

				try {
					if ( Long.parseLong(s) == ((Long)o).longValue() ) {
						return true;
					}
				} catch (Exception e) {}

			} else if ( o instanceof Double ) {

				try {
					if ( Double.parseDouble(s) == ((Double)o).doubleValue() ) {
						return true;
					}
				} catch (Exception e) {}
			}

		}

		return false;
	}

	public static boolean testValue(String s, String test, int operator) {

		switch(operator) {
			case AppGuardianConfiguration.OPERATOR_EQ:

				return test.equals(s);

			case AppGuardianConfiguration.OPERATOR_CONTAINS:

				return test.contains(s);

		}

		return false;
	}

}
