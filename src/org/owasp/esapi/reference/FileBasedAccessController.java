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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
 * methods provided in the IAccessController interface.
 * <P>
 * This reference implementation uses a simple scheme for specifying the rules.
 * The first step is to create a namespace for the resources being accessed. For
 * files and URL's, this is easy as they already have a namespace. Be extremely
 * careful about canonicalizing when relying on information from the user in an
 * access ctnrol decision.
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
 * the IAccessController interface. These files are located in the ESAPI
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
 */
public class FileBasedAccessController implements org.owasp.esapi.AccessController {

	/** The url map. */
	private Map urlMap = new HashMap();

	/** The function map. */
	private Map functionMap = new HashMap();

	/** The data map. */
	private Map dataMap = new HashMap();

	/** The file map. */
	private Map fileMap = new HashMap();

	/** The service map. */
	private Map serviceMap = new HashMap();

	/** The deny. */
	private Rule deny = new Rule();

	/** The logger. */
	private Logger logger = ESAPI.getLogger("AccessController");

	public FileBasedAccessController() {
	}

    public boolean isAuthorizedForURL(String url) {
    	try {
    		assertAuthorizedForURL( url );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
    
    public boolean isAuthorizedForFunction(String functionName) {
    	try {
    		assertAuthorizedForFunction( functionName );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }

    public boolean isAuthorizedForData(String key) {
    	try {
    		assertAuthorizedForData( key );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }

    public boolean isAuthorizedForFile(String filepath) {
    	try {
    		assertAuthorizedForFile( filepath );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
    
    public boolean isAuthorizedForService(String serviceName) {
    	try {
    		assertAuthorizedForService( serviceName );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForURL(java.lang.String,
	 *      java.lang.String)
	 */
    public void assertAuthorizedForURL(String url) throws AccessControlException {
		if (urlMap==null || urlMap.isEmpty()) {
			urlMap = loadRules("URLAccessRules.txt");
		}
		if ( !matchRule(urlMap, url) ) {
			throw new AccessControlException("Not authorized for URL", "Not authorized for URL: " + url );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFunction(java.lang.String,
	 *      java.lang.String)
	 */
    public void assertAuthorizedForFunction(String functionName) throws AccessControlException {
    	if (functionMap==null || functionMap.isEmpty()) {
			functionMap = loadRules("FunctionAccessRules.txt");
		}
		if ( !matchRule(functionMap, functionName) ) {
			throw new AccessControlException("Not authorized for function", "Not authorized for function: " + functionName );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForData(java.lang.String)
	 */
    public void assertAuthorizedForData(String key) throws AccessControlException {
		if (dataMap==null || dataMap.isEmpty()) {
			dataMap = loadRules("DataAccessRules.txt");
		}
		if ( !matchRule(dataMap, key) ) {
			throw new AccessControlException("Not authorized for function", "Not authorized for data: " + key );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFile(java.lang.String,
	 *      java.lang.String)
	 */
    public void assertAuthorizedForFile(String filepath) throws AccessControlException {
		if (fileMap==null || fileMap.isEmpty()) {
			fileMap = loadRules("FileAccessRules.txt");
		}
		if ( !matchRule(fileMap, filepath.replaceAll("\\\\","/"))) {
			throw new AccessControlException("Not authorized for file", "Not authorized for file: " + filepath );
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForBackendService(java.lang.String,
	 *      java.lang.String)
	 */
    public void assertAuthorizedForService(String serviceName) throws AccessControlException {    	
		if (serviceMap==null || serviceMap.isEmpty()) {
			serviceMap = loadRules("ServiceAccessRules.txt");
		}
		if ( !matchRule(serviceMap, serviceName ) ) {
			throw new AccessControlException("Not authorized for service", "Not authorized for service: " + serviceName );
		}
	}

	/**
	 * Match rule.
	 * 
	 * @param map
	 *            the map
	 * @param path
	 *            the path
	 * 
	 * @return true, if successful
	 * 
	 * @throws AccessControlException
	 *             the access control exception
	 */
	private boolean matchRule(Map map, String path) {
		// get users roles
		User user = ESAPI.authenticator().getCurrentUser();
		Set roles = user.getRoles();
		// search for the first rule that matches the path and rules
		Rule rule = searchForRule(map, roles, path);
		return rule.allow;
	}

	/**
	 * Search for rule. Four mapping rules are used in order: - exact match,
	 * e.g. /access/login - longest path prefix match, beginning / and ending
	 * /*, e.g. /access/* or /* - extension match, beginning *., e.g. *.css -
	 * default servlet, specified by the single character pattern /
	 * 
	 * @param map
	 *            the map
	 * @param roles
	 *            the roles
	 * @param path
	 *            the path
	 * 
	 * @return the rule
	 * 
	 * @throws AccessControlException
	 *             the access control exception
	 */
	private Rule searchForRule(Map map, Set roles, String path) {
		String canonical = null;
		try {
		    canonical = ESAPI.encoder().canonicalize(path);
		} catch (EncodingException e) {
		    logger.warning( Logger.SECURITY, "Failed to canonicalize input: " + path );
		}
		
		String part = canonical;
		while (part.endsWith("/")) {
			part = part.substring(0, part.length() - 1);
		}

		if (part.indexOf("..") != -1) {
			throw new IntrusionException("Attempt to manipulate access control path", "Attempt to manipulate access control path: " + path );
		}
		
		// extract extension if any
		String extension = "";
		int extIndex = part.lastIndexOf(".");
		if (extIndex != -1) {
			extension = part.substring(extIndex + 1);
		}

		// Check for exact match - ignore any ending slash
		Rule rule = (Rule) map.get(part);

		// Check for ending with /*
		if (rule == null)
			rule = (Rule) map.get(part + "/*");

		// Check for matching extension rule *.ext
		if (rule == null)
			rule = (Rule) map.get("*." + extension);

		// if rule found and user's roles match rules' roles, return the rule
		if (rule != null && overlap(rule.roles, roles))
			return rule;

		// rule hasn't been found - if there are no more parts, return a deny
		int slash = part.lastIndexOf('/');
		if ( slash == -1 ) {
			return deny;
		}
		
		// if there are more parts, strip off the last part and recurse
		part = part.substring(0, part.lastIndexOf('/'));
		
		// return default deny
		if (part.length() <= 1) {
			return deny;
		}
		
		return searchForRule(map, roles, part);
	}

	/**
	 * Return true if there is overlap between the two sets.
	 * 
	 * @param ruleRoles
	 *            the rule roles
	 * @param userRoles
	 *            the user roles
	 * 
	 * @return true, if successful
	 */
	private boolean overlap(Set ruleRoles, Set userRoles) {
		if (ruleRoles.contains("any")) {
			return true;
		}
		Iterator i = userRoles.iterator();
		while (i.hasNext()) {
			String role = (String) i.next();
			if (ruleRoles.contains(role)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Load rules.
	 * 
	 * @param f
	 *            the f
	 * 
	 * @return the hash map
	 * 
	 * @throws AccessControlException
	 *             the access control exception
	 */
	private Map loadRules(String ruleset) {
		Map map = new HashMap();
		InputStream is = null;
		try {
			is = new FileInputStream(new File(ESAPI.securityConfiguration().getResourceDirectory(), ruleset));
			String line = "";
			while ((line = ESAPI.validator().safeReadLine(is, 500)) != null) {
				if (line.length() > 0 && line.charAt(0) != '#') {
					Rule rule = new Rule();
					String[] parts = line.split("\\|");
					// fix Windows paths
					rule.path = parts[0].trim().replaceAll("\\\\", "/");
					rule.roles.add(parts[1].trim().toLowerCase());
					String action = parts[2].trim();
					rule.allow = action.equalsIgnoreCase("allow");
					if (map.containsKey(rule.path)) {
						logger.warning( Logger.SECURITY, "Problem in access control file. Duplicate rule ignored: " + rule);
					} else {
						map.put(rule.path, rule);
					}
				}
			}
		} catch (Exception e) {
			logger.warning( Logger.SECURITY, "Problem in access control file : " + ruleset, e );
		} finally {
			try {
				if (is != null) {
					is.close();
				}
			} catch (IOException e) {
				logger.warning(Logger.SECURITY, "Failure closing access control file : " + ruleset, e);
			}
		}
		return map;
	}

	/**
	 * The Class Rule.
	 */
	private class Rule {

		/** The path. */
		protected String path = "";

		/** The roles. */
		protected Set roles = new HashSet();

		/** The allow. */
		protected boolean allow = false;

		/**
		 * Creates a new Rule object.
		 */
		protected Rule() {
			// to replace synthetic accessor method
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#toString()
		 */
		public String toString() {
			return "URL:" + path + " | " + roles + " | " + (allow ? "allow" : "deny");
		}
	}
}
