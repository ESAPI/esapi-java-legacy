/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2010 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Patrick Higgins
 * @created 2010
 */
package org.owasp.esapi;

/**
 * The ExecuteResult class encapsulates the pieces of data that can be returned
 * from a process executed by the Executor interface.
 *
 * This class is immutable for thread-safety.
 *
 * @author Patrick Higgins
 * @since Aug 25, 2010
 */
public class ExecuteResult {
    
	private final int exitValue;
	private final String output;
	private final String errors;

	/**
	 * Constructs an ExecuteResult from the given values.
	 *
	 * @param exitValue
	 *            the code from java.lang.Process.exitValue()
	 * @param output
	 *            the contents read from java.lang.Process.getInputStream()
	 * @param errors
	 *            the contents read from java.lang.Process.getErrorStream()
	 */
	public ExecuteResult(int exitValue, String output, String errors) {
		this.exitValue = exitValue;
		this.output = output;
		this.errors = errors;
	}

	/**
	 * @return the code from java.lang.Process.exitValue()
	 */
	public int getExitValue() {
		return exitValue;
	}

	/**
	 * @return the contents read from java.lang.Process.getInputStream()
	 */
	public String getOutput() {
		return output;
	}

	/**
	 * @return the contents read from java.lang.Process.getErrorStream()
	 */
	public String getErrors() {
		return errors;
	}
	
	@Override
	public String toString() {
		return "ExecuteResult[exitValue="+exitValue+",output="+output+",errors="+errors+"]";
	}

}
