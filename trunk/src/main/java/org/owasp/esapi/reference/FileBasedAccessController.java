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
package org.owasp.esapi.reference;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Logger;
import org.owasp.esapi.User;
import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;

/**
 * Reference implementation of the AccessController interface. This reference
 * implementation uses a simple model for specifying a set of access control
 * rules. Many organizations will want to create their own implementation of the
 * methods provided in the AccessController interface.
 * <P>
 * This reference implementation uses a simple scheme for specifying the rules.
 * The first step is to create a namespace for the resources being accessed. For
 * files and URL's, this is easy as they already have a namespace. Be extremely
 * careful about canonicalizing when relying on information from the user in an
 * access control decision.
 * <P>
 * For functions, data, and services, you will have to come up with your own
 * namespace for the resources being accessed. You might simply define a flat
 * namespace with a list of category names. For example, you might specify
 * 'FunctionA', 'FunctionB', and 'FunctionC'. Or you can create a richer
 * namespace with a hierarchical structure, such as:
 * <P>
 * /functions
 * <ul>
 * <li>purchasing</li>
 * <li>shipping</li>
 * <li>inventory</li>
 * </ul>
 * /admin
 * <ul>
 * <li>createUser</li>
 * <li>deleteUser</li>
 * </ul>
 * Once you've defined your namespace, you have to work out the rules that
 * govern access to the different parts of the namespace. This implementation
 * allows you to attach a simple access control list (ACL) to any part of the
 * namespace tree. The ACL lists a set of roles that are either allowed or
 * denied access to a part of the tree. You specify these rules in a textfile
 * with a simple format.
 * <P>
 * There is a single configuration file supporting each of the five methods in
 * the AccessController interface. These files are located in the ESAPI
 * resources directory as specified when the JVM was started. The use of a
 * default deny rule is STRONGLY recommended. The file format is as follows:
 * 
 * <pre>
 * path          | role,role   | allow/deny | comment
 * ------------------------------------------------------------------------------------
 * /banking/*    | user,admin  | allow      | authenticated users can access /banking
 * /admin        | admin       | allow      | only admin role can access /admin
 * /             | any         | deny       | default deny rule
 * </pre>
 * 
 * To find the matching rules, this implementation follows the general approach
 * used in Java EE when matching HTTP requests to servlets in web.xml. The
 * four mapping rules are used in the following order:
 * <ul>
 * <li>exact match, e.g. /access/login</li>
 * <li>longest path prefix match, beginning / and ending /*, e.g. /access/* or /*</li>
 * <li>extension match, beginning *., e.g. *.css</li>
 * <li>default rule, specified by the single character pattern /</li>
 * </ul>
 * 
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 * @since June 1, 2007
 * @see org.owasp.esapi.AccessController
 * @deprecated
 */
public class FileBasedAccessController implements org.owasp.esapi.AccessController {
	
	/**
	 * This class is deprecated. 
	 */
	public boolean isAuthorized(Object key, Object runtimeParameter) {
		return false;
	}
	/**
	 * This class is deprecated.
	 */
	public void assertAuthorized(Object key, Object runtimeParameter) throws AccessControlException{
		throw new AccessControlException("Access Denied", "Method Not implemented");
	}
	
	/** The logger. */
	private Logger logger = ESAPI.getLogger("AccessController");

    /**
     *
     */
    public FileBasedAccessController() {
	}

	/**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForURL(String url) {
    	try {
    		assertAuthorizedForURL( url );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForFunction(String functionName) {
    	try {
    		assertAuthorizedForFunction( functionName );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
        
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForData(String action, Object data){
    	return ESAPI.accessController().isAuthorizedForData(action, data);
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForFile(String filepath) {
    	return ESAPI.accessController().isAuthorizedForFile( filepath );
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForService(String serviceName) {
    	return ESAPI.accessController().isAuthorizedForService( serviceName );
    }
	
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForURL(String url) throws AccessControlException {
    	ESAPI.accessController().assertAuthorizedForURL(url);
	}

    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForFunction(String functionName) throws AccessControlException {
    	ESAPI.accessController().assertAuthorizedForFunction(functionName);
	}
  
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForData(String action, Object data) throws AccessControlException{
    	ESAPI.accessController().assertAuthorizedForData(action, data);    	
    }
    
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForFile(String filepath) throws AccessControlException {
    	ESAPI.accessController().assertAuthorizedForFile(filepath);
	}

    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForService(String serviceName) throws AccessControlException {    	
    	ESAPI.accessController().assertAuthorizedForService(serviceName);
	}
}
