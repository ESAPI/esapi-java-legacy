/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * http://www.owasp.org/esapi.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the LGPL. You should read and accept the
 * LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @created 2007
 */
package org.owasp.esapi;

import java.io.File;
import java.util.List;


/**
 * The Executor interface is used to run an OS command with less security risk.
 * Implementations should do as much as possible to minimize the risk of
 * injection into either the command or parameters. In addition, implementations
 * should timeout after a specified time period in order to help prevent denial
 * of service attacks. The class should perform logging and error handling as
 * well. Finally, implementation should handle errors and generate an
 * ExecutorException with all the necessary information.
 * <P>
 * <img src="doc-files/Executor.jpg" height="600">
 * <P>
 * 
 * @author Jeff Williams (jeff.williams .at. aspectsecurity.com) <a
 *         href="http://www.aspectsecurity.com">Aspect Security</a>
 * @since June 1, 2007
 */
public interface Executor {

	/**
	 * Executes a system command after checking that the executable exists and
	 * that the parameters have not been subject to injection with untrusted
	 * user data. Implementations shall change to the specified working
	 * directory before invoking the command. Also, processes should be
	 * interrupted after the specified timeout period has elapsed.
	 * 
	 * @param command
	 *            the command
	 * @param params
	 *            the params
	 * @param workdir
	 *            the workdir
	 * @param timeoutSeconds
	 *            the timeout seconds
	 * 
	 * @return the string
	 * 
	 * @throws ExecutorException
	 *             the service exception
	 */
	String executeSystemCommand(File executable, List params, File workdir, int timeoutSeconds) throws ExecutorException;

}
