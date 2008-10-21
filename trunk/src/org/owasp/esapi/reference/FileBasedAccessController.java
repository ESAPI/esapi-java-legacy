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
    
    public boolean isAuthorizedForData(String action, Object data){
    	try{
    		assertAuthorizedForData( action, data );
    		return true;
    	}catch ( Exception e ) {
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
	 * @see org.owasp.esapi.interfaces.AccessController#isAuthorizedForURL(java.lang.String,
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
	 * @see org.owasp.esapi.interfaces.AccessController#isAuthorizedForFunction(java.lang.String,
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

	/**
	 * Checks if the current user is authorized to access the referenced data.  This method simply returns if access is authorized.
	 * It throws an AccessControlException if access is not authorized, or the referenced data does not exist.
	 * 
	 * This method enforces the following access control policy as defined in the DataAccessRules.txt configuration file:
	 * 	1) This config file defines the name space of all the data sets for this system
	 * 	2) This file also defines which user roles are either allowed or denied access to each data resource
	 * 	3) This method checks to see if the resource exists in the configuration file and if not, throws and AccessControlException
	 * 	4) It checks the policy to see if the user is authorized and if not, throws and AccessControlException
	 * 	5) A default rule built into the method is that if the policy does not specifically grant access, access is denied,
	 * 		and an AccessControlException is thrown
	 * 
	 * @param key
	 * 		the name of the target data object
	 * 
	 * @throws AccessControlException
	 * 		if access is not permitted
	 * 
	 * @see org.owasp.esapi.AccessController#isAuthorizedForData(java.lang.String)
	 */
    public void assertAuthorizedForData(String key) throws AccessControlException {
		if (dataMap==null || dataMap.isEmpty()) {
			dataMap = loadDataRules("DataAccessRules.txt");
		}
		if ( !matchRule(dataMap, key) ) {
			throw new AccessControlException("Not authorized for function", "Not authorized for data: " + key );
		}
	}
    
    public void assertAuthorizedForData(String action, Object data) throws AccessControlException{
    	if (dataMap==null || dataMap.isEmpty()) {
			dataMap = loadDataRules("DataAccessRules.txt");
    	}		
    	    	
    	if( !matchRule(dataMap, (Class) data, action ) ){
    		throw new AccessControlException("Not authorized for data", "Not authorized for data: " + (Class)data);
    	}
    	
    }
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.esapi.interfaces.AccessController#isAuthorizedForFile(java.lang.String,
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
	 * @see org.owasp.esapi.interfaces.AccessController#isAuthorizedForBackendService(java.lang.String,
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
	
	private boolean matchRule(Map map, Class clazz, String action) {
		// get users roles
		User user = ESAPI.authenticator().getCurrentUser();
		Set roles = user.getRoles();
		// search for the first rule that matches the path and rules
		Rule rule = searchForRule(map, roles, clazz, action);
		return rule != null;
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
		    logger.warning( Logger.SECURITY, false, "Failed to canonicalize input: " + path );
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
	 *            the paths
	 * 
	 * @return the rule
	 * 
	 * @throws AccessControlException
	 *             the access control exception
	 */
	private Rule searchForRule(Map map, Set roles, Class clazz, String action) {

		// Check for exact match - ignore any ending slash
		Rule rule = (Rule) map.get(clazz);
		if( ( rule != null ) && ( overlap(rule.actions, action) ) && ( overlap(rule.roles, roles) )){
			return rule;
		}
		return null;
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
	
	private boolean overlap( List ruleActions, String action){
		if( ruleActions.contains(action) )
			return true;
		return false;
	}

	/**
	 * Load rules.
	 * 
	 * @param ruleset
	 *            the ruleset
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
						logger.warning( Logger.SECURITY, false, "Problem in access control file. Duplicate rule ignored: " + rule);
					} else {
						map.put(rule.path, rule);
					}
				}
			}
		} catch (Exception e) {
			logger.warning( Logger.SECURITY, false, "Problem in access control file : " + ruleset, e );
		} finally {
			try {
				if (is != null) {
					is.close();
				}
			} catch (IOException e) {
				logger.warning(Logger.SECURITY, false, "Failure closing access control file : " + ruleset, e);
			}
		}
		return map;
	}
	
	/**
	 * Load Data rules.  Class may only appear once on the list of rules.
	 * 
	 * @param ruleset
	 *            the ruleset
	 * 
	 * @return the hash map
	 */
	private Map loadDataRules(String ruleset) {
		Map map = new HashMap();
		InputStream is = null;

		try {
			is = new FileInputStream(new File(ESAPI.securityConfiguration().getResourceDirectory(), ruleset));
			String line = "";
			while ((line = ESAPI.validator().safeReadLine(is, 500)) != null) {
				if (line.length() > 0 && line.charAt(0) != '#') {
					Rule rule = new Rule();
					String[] parts = line.split("\\|");
					rule.clazz = Class.forName(parts[0].trim());
					
					List roles = commaSplit(parts[1].trim().toLowerCase());
					for(int x = 0; x < roles.size(); x++)
						rule.roles.add(roles.get(x));
					
					List action = commaSplit(parts[2].trim().toLowerCase());
					for(int x = 0; x < action.size(); x++)
						rule.actions.add(((String) action.get(x)).trim());
					
					if (map.containsKey(rule.path)) {
						logger.warning( Logger.SECURITY, false, "Problem in access control file. Duplicate rule ignored: " + rule);
					} else {
						map.put(rule.clazz, rule);		
					}
				}
			}
		} catch (Exception e) {
			logger.warning( Logger.SECURITY, false, "Problem in access control file : " + ruleset, e );
		} finally {
			
			try {
				if (is != null) {
					is.close();
				}
			} catch (IOException e) {
				logger.warning(Logger.SECURITY, false, "Failure closing access control file : " + ruleset, e);
			}
		}
		return map;
	}
	
	private List commaSplit(String input){
		String[] array = input.split(",");
		return Arrays.asList(array);
	}
	
	/**
	 * The Class Rule.
	 */
	private class Rule {

		
		protected String path = "";

		
		protected Set roles = new HashSet();

		
		protected boolean allow = false;
		
		
		protected Class clazz = null;
		
		
		protected List actions = new ArrayList();

		/**
		 * 
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
