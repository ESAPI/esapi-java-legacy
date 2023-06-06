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
package org.owasp.esapi.http;

import java.io.IOException;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

/**
 *
 * @author jwilliams
 */
public class MockRequestDispatcher implements RequestDispatcher {

    /**
     *
     * @param request
     * @param response
     * @throws jakarta.servlet.ServletException
     * @throws java.io.IOException
     */
    public void forward(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        System.out.println( "Forwarding" );
    }

    /**
     *
     * @param request
     * @param response
     * @throws jakarta.servlet.ServletException
     * @throws java.io.IOException
     */
    public void include(ServletRequest request, ServletResponse response) throws ServletException, IOException {
        System.out.println( "Including" );
    }
}


