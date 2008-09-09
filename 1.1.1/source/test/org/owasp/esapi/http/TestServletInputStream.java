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
package org.owasp.esapi.http;

import javax.servlet.ServletInputStream;
import java.io.IOException;

public class TestServletInputStream extends ServletInputStream {

    private byte[] body;

    private int next;

    /**
     * constructor
     * @param body
     */
    public TestServletInputStream(byte[] body) {
        this.body = body;
    }

    /**
     * read
     */
    public int read() throws IOException {
        if (next < body.length) {
            return body[next++];
        } else {
            return -1;
        }
    }
}
