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
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.owasp.esapi.errors.AccessControlException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

/**
 * Reference implementation of the IAccessController interface. This reference
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
 * @see org.owasp.esapi.interfaces.IAccessController
 */
public class AccessController implements org.owasp.esapi.interfaces.IAccessController {

	/** The instance. */
	private static AccessController instance = new AccessController();

	/** The resource directory. */
	private static final File resourceDirectory = SecurityConfiguration.getInstance().getResourceDirectory();

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
	private static Logger logger = Logger.getLogger("ESAPI", "AccessController");

	/**
	 * Hide the constructor for the Singleton pattern.
	 */
	protected AccessController() {
		// hidden
	}

	/**
	 * Gets the single instance of AccessController.
	 * 
	 * @return single instance of AccessController
	 */
	public static AccessController getInstance() {
		return instance;
	}

	
	// FIXME: consider adding flag for logging
	// FIXME: perhaps an enumeration for context (i.e. the layer the call is made from)
	
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForURL(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean isAuthorizedForURL(String url) {
		if (urlMap.isEmpty()) {
			try {
				urlMap = loadRules(new File(resourceDirectory, "URLAccessRules.txt"));
			} catch (AccessControlException ex) {
				return false;
			}
		}
		try {
			return matchRule(urlMap, url);
		} catch (AccessControlException ex) {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFunction(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean isAuthorizedForFunction(String functionName) {
		if (functionMap.isEmpty()) {
			try {
				functionMap = loadRules(new File(resourceDirectory, "FunctionAccessRules.txt"));
			} catch (AccessControlException ex) {
				return false;
			}
		}
		try {
			return matchRule(functionMap, functionName);
		} catch (AccessControlException ex) {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForData(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean isAuthorizedForData(String key) {
		if (dataMap.isEmpty()) {
			try {
				dataMap = loadRules(new File(resourceDirectory, "DataAccessRules.txt"));
			} catch (AccessControlException ex) {
				return false;
			}
		}
		try {
			return matchRule(dataMap, key);
		} catch (AccessControlException ex) {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForFile(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean isAuthorizedForFile(String filepath) {
		if (fileMap.isEmpty()) {
			try {
				fileMap = loadRules(new File(resourceDirectory, "FileAccessRules.txt"));
			} catch (AccessControlException ex) {
				return false;
			}
		}
		try {
			// FIXME: AAA think about canonicalization here - use Java file canonicalizer
			// remember that Windows paths have \ instad of /
			return matchRule(fileMap, filepath.replaceAll("\\\\", "/"));
		} catch (AccessControlException ex) {
			return false;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.IAccessController#isAuthorizedForBackendService(java.lang.String,
	 *      java.lang.String)
	 */
	public boolean isAuthorizedForService(String serviceName) {
		if (serviceMap.isEmpty()) {
			try {
				serviceMap = loadRules(new File(resourceDirectory, "ServiceAccessRules.txt"));
			} catch (AccessControlException ex) {
				return false;
			}
		}
		try {
			return matchRule(serviceMap, serviceName);
		} catch (AccessControlException ex) {
			return false;
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
	private boolean matchRule(Map map, String path) throws AccessControlException {
		// get users roles
		User user = Authenticator.getInstance().getCurrentUser();
		if (user == null) {
			return false;
        }
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
	private Rule searchForRule(Map map, Set roles, String path) throws AccessControlException {
		String canonical = Encoder.getInstance().canonicalize(path);
		
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

		// if rule has not been found, strip off the last element and recurse
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
	private Map loadRules(File f) throws AccessControlException {
		Map map = new HashMap();
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(f);
			String line = "";
			while ((line = Validator.getInstance().safeReadLine(fis, 500)) != null) {
				if (line.length() > 0 && line.charAt(0) != '#') {
					Rule rule = new Rule();
					String[] parts = line.split("\\|");
					// fix Windows paths
					rule.path = parts[0].trim().replaceAll("\\\\", "/");
					rule.roles.add(parts[1].trim().toLowerCase());
					String action = parts[2].trim();
					rule.allow = action.equalsIgnoreCase("allow");
					if (map.containsKey(rule.path)) {
						throw new AccessControlException("Access control failure", "Problem in access control file. Duplicate rule " + rule);
					}
					map.put(rule.path, rule);
				}
			}
			return map;
		} catch (IOException e) {
			throw new AccessControlException("Access control failure", "Failure loading access control file " + f, e);
		} catch (ValidationException e1) {
			throw new AccessControlException("Access control failure", "Failure loading access control file " + f, e1);
		} finally {
			try {
				if (fis != null) {
					fis.close();
				}
			} catch (IOException e) {
				logger.logWarning(Logger.SECURITY, "Failure closing access control file: " + f, e);
			}
		}
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
