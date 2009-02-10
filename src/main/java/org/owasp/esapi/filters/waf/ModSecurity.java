/*
 * OWASP ESAPI WAF
 *
 * ModSecurity for Java M3 (Milestone 3)
 * Copyright (c) 2004-2005 Ivan Ristic <ivanr@webkreator.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

package org.owasp.esapi.filters.waf;

import java.io.IOException;
import java.io.File;
import java.util.Date;
import java.util.Enumeration;
import java.text.SimpleDateFormat;
import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.esapi.filters.waf.jak.*;

public class ModSecurity extends Jak implements JakModule, DirectiveHandler {

    public final static int OFF = 0;
    public final static int ON = 1;
    public final static int RELEVANT_ONLY = 2;

    private FilterConfig filterConfig;

    private boolean filterEngine = false;

    private boolean filterScanPost = false;

    private int maxContentLength = -1;

    private String uploadTmpDir = null;

    private String uploadStorageDir = null;

    private int uploadKeepFiles = OFF;

    private Object[] debugLogModules;

    private Object[] inspectorModules;

    public ModSecurity(FilterConfig filterConfig) {
        super();
        this.filterConfig = filterConfig;
    }

    public FilterConfig getFilterConfig() {
        return filterConfig;
    }

    public void handleDirective(Configuration config, Directive directive)
            throws JakException {

        if (directive.getName().compareTo("SecFilterEngine") == 0) {
            filterEngine = directive.getBooleanToken(1);
        }
        else if (directive.getName().compareTo("SecFilterScanPOST") == 0) {
            filterScanPost = directive.getBooleanToken(1);
        }
        else if (directive.getName().compareTo("SecMaxContentLength") == 0) {
            maxContentLength = directive.getIntegerToken(1);
        }
        else if (directive.getName().compareTo("SecUploadTmpDir") == 0) {
            // TODO does the folder exist & can we write to it?
            uploadTmpDir = directive.getToken(1);
            uploadTmpDir = getFilterConfig().getServletContext().getRealPath(uploadTmpDir);
        }
        else if (directive.getName().compareTo("SecUploadKeepFiles") == 0) {
            String param = directive.getToken(1);
            if (param.compareToIgnoreCase("On") == 0) {
                uploadKeepFiles = ON;
            }
            else if (param.compareToIgnoreCase("Off") == 0) {
                uploadKeepFiles = OFF;
            }
            else if (param.compareToIgnoreCase("RelevantOnly") == 0) {
                uploadKeepFiles = RELEVANT_ONLY;
            }
            else {
                throw new JakException("Module ModSecurity: invalid value for directive SecUploadKeepFiles: " + param, directive);
            }
        }
        else if (directive.getName().compareTo("SecUploadStorageDir") == 0) {
            // TODO does the folder exist & can we write to it?
            uploadStorageDir = directive.getToken(1);
            uploadStorageDir = getFilterConfig().getServletContext().getRealPath(uploadStorageDir);
        }
        else {
            throw new JakException("Module ModSecurity: don't know how to handle directive " + directive.getName());
        }
    }

    public void init(Configuration config) throws Exception {
        config.registerDirectiveTemplate("SecFilterEngine", DirectiveTemplate.FLAG, this);
        config.registerDirectiveTemplate("SecFilterScanPOST", DirectiveTemplate.FLAG, this);
        config.registerDirectiveTemplate("SecMaxContentLength", DirectiveTemplate.TAKE1, this);
        config.registerDirectiveTemplate("SecUploadTmpDir", DirectiveTemplate.TAKE1, this);
        config.registerDirectiveTemplate("SecUploadStorageDir", DirectiveTemplate.TAKE1, this);
        config.registerDirectiveTemplate("SecUploadKeepFiles", DirectiveTemplate.TAKE1, this);
    }

	public void postInit() {
	    // find modules implementing the DebugLog interface
	    debugLogModules = getModules(DebugLog.class);
	    // TODO throw exception if debugLogModules empty
	    inspectorModules = getModules(Inspector.class);
	}

	public void start() {}

	public void stop() {}

	public void destroy() {}

	HttpTransaction initRequest(ServletRequest req, ServletResponse res) {
	    HttpTransaction tran = new HttpTransaction(this, req, res);
	    if (maxContentLength != -1) tran.msReq.setMaxContentLength(maxContentLength);
	    if (uploadTmpDir != null) tran.msReq.setTmpPath(uploadTmpDir);
	    return tran;
	}

	int processBefore(HttpTransaction tran) throws IOException, ServletException {
	    int rc;

	    // are we supposed to run?
	    if (filterEngine == false) return Inspector.ACTION_NONE;

	    // phase 1 (pre-request)
	    log(2, "ModSecurity: Entering phase 1 (preRequest)", tran);
	    rc = processPhase(1, tran);
	    if ((rc == Inspector.ACTION_WARN)||(rc == Inspector.ACTION_STOP)) tran.setRelevant(true);
	    if ((rc != Inspector.ACTION_NONE)&&(rc != Inspector.ACTION_WARN)) return rc;

	    // phase 2 (request headers)
	    log(2, "ModSecurity: Entering phase 2 (requestHeaders)", tran);
	    rc = processPhase(2, tran);
	    if ((rc == Inspector.ACTION_WARN)||(rc == Inspector.ACTION_STOP)) tran.setRelevant(true);
	    if ((rc != Inspector.ACTION_NONE)&&(rc != Inspector.ACTION_WARN)) return rc;

	    // phase 3 (request body)
	    log(2, "ModSecurity: Entering phase 3 (requestBody)", tran);
	    if (filterScanPost) tran.msReq.readBody();
	    rc = processPhase(3, tran);
	    if ((rc == Inspector.ACTION_WARN)||(rc == Inspector.ACTION_STOP)) tran.setRelevant(true);
	    if ((rc != Inspector.ACTION_NONE)&&(rc != Inspector.ACTION_WARN)) return rc;

	    return Inspector.ACTION_NONE;
	}

	int processAfter(HttpTransaction tran) throws IOException, ServletException {
	    int rc;

	    // are we supposed to run?
	    if (filterEngine == false) return Inspector.ACTION_NONE;

	    // phase 4 (response)
	    log(2, "ModSecurity: Entering phase 4 (responseBody)", tran);
	    rc = processPhase(4, tran);
	    if (rc != Inspector.ACTION_NONE) return rc;

	    return Inspector.ACTION_NONE;
	}

	void processLogging(HttpTransaction tran) throws IOException, ServletException {
	    try {
	        // phase 5 (logging)
	        log(2, "ModSecurity: Entering phase 5 (logging)", tran);
	        processPhase(5, tran);
	        storeUploadedFiles(tran);
	    } catch(Exception e) {
	        throw new ServletException(e);
	    }
	}

	public void storeUploadedFiles(HttpTransaction tran) {
	    if (uploadKeepFiles == OFF) return;
	    if ((uploadKeepFiles == RELEVANT_ONLY)&&(tran.isRelevant() == false)) return;

        // TODO error if (uploadStorageDir == null);

	    for (Enumeration e = tran.msReq.getFileNames(); e.hasMoreElements();) {
            String fieldName = (String)e.nextElement();
            String fileName = tran.msReq.getFileSystemName(fieldName);
            File fileCurrent = tran.msReq.getFile(fieldName);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd-HHmmss");
            // TODO sanitize fileName
            File fileNew = new File(uploadStorageDir, sdf.format(new Date()) + "-" + tran.msReq.getRemoteAddr() + "-" + fileName);
            // TODO use a custom function for copying
        }
	}

	public void log(int level, String msg) {
	    log(level, msg, null);
	}

	public void log(int level, String msg, HttpTransaction tran) {
	    // log severe messages to the servlet context
	    if (level == 1) {
	        filterConfig.getServletContext().log("ModSecurity: " + msg);
	    }

        if (debugLogModules != null) {
	        // pass the message to registered debug loggers
    	    for(int i = 0; i < debugLogModules.length; i++) {
	            ((DebugLog)debugLogModules[i]).log(level, msg, tran);
	        }
	    }
	}

	private int processPhase(int phase, HttpTransaction tran) throws IOException, ServletException {
	    try {
	        for(int i = 0; i < inspectorModules.length; i++) {
	            int rc = ((Inspector)inspectorModules[i]).inspect(phase, tran);
	            if (rc != Inspector.ACTION_NONE) return rc;
	        }
	        return Inspector.ACTION_NONE;
	    } catch(Exception e) {
	        throw new ServletException(e);
	    }
	}
}

