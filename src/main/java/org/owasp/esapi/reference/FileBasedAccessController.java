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

	/** A rule containing "deny". */
	private Rule deny = new Rule();

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
     *
     * @param key
     * @return
     */
    public boolean isAuthorizedForData(String key) {
    	try {
    		assertAuthorizedForData( key );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForData(String action, Object data){
    	try{
    		assertAuthorizedForData( action, data );
    		return true;
    	}catch ( Exception e ) {
    		return false;
    	}
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForFile(String filepath) {
    	try {
    		assertAuthorizedForFile( filepath );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
    
    /**
	* {@inheritDoc}
	*/
    public boolean isAuthorizedForService(String serviceName) {
    	try {
    		assertAuthorizedForService( serviceName );
    		return true;
    	} catch ( Exception e ) {
    		return false;
    	}
    }
	
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForURL(String url) throws AccessControlException {
		if (urlMap==null || urlMap.isEmpty()) {
			urlMap = loadRules("URLAccessRules.txt");
		}
		if ( !matchRule(urlMap, url) ) {
			throw new AccessControlException("Not authorized for URL", "Not authorized for URL: " + url );
		}
	}

    /**
	* {@inheritDoc}
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
	* {@inheritDoc}
     *
     * @param key
     * @throws AccessControlException
     */
    public void assertAuthorizedForData(String key) throws AccessControlException {
		if (dataMap==null || dataMap.isEmpty()) {
			dataMap = loadDataRules("DataAccessRules.txt");
		}
		if ( !matchRule(dataMap, key) ) {
			throw new AccessControlException("Not authorized for function", "Not authorized for data: " + key );
		}
	}
  
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForData(String action, Object data) throws AccessControlException{
    	if (dataMap==null || dataMap.isEmpty()) {
			dataMap = loadDataRules("DataAccessRules.txt");
    	}		
    	    	
    	if( !matchRule(dataMap, (Class) data, action ) ){
    		throw new AccessControlException("Not authorized for data", "Not authorized for data: " + (Class)data);
    	}
    	
    }
    
    /**
	* {@inheritDoc}
	*/
    public void assertAuthorizedForFile(String filepath) throws AccessControlException {
		if (fileMap==null || fileMap.isEmpty()) {
			fileMap = loadRules("FileAccessRules.txt");
		}
		if ( !matchRule(fileMap, filepath.replaceAll("\\\\","/"))) {
			throw new AccessControlException("Not authorized for file", "Not authorized for file: " + filepath );
		}
	}

    /**
	* {@inheritDoc}
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
	 * Checks to see if the current user has access to the specified data, File, Object, etc.
	 * If the User has access, as specified by the map parameter, this method returns true.  If the 
	 * User does not have access or an exception is thrown, false is returned.
	 * 
	 * @param map
	 *       the map containing access rules
	 * @param path
	 *       the path of the requested File, URL, Object, etc.
	 * 
	 * @return 
	 * 		true, if the user has access, false otherwise
	 * 
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
	 * Checks to see if the current user has access to the specified Class and action.
	 * If the User has access, as specified by the map parameter, this method returns true.
     * If the User does not have access or an exception is thrown, false is returned.
	 * 
	 * @param map
	 *       the map containing access rules
	 * @param clazz
	 *       the Class being requested for access
	 * @param action
	 * 		 the action the User has asked to perform
	 * @return 
	 * 		true, if the user has access, false otherwise
	 * 
	 */
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
	 *       the map containing access rules
	 * @param roles
	 *       the roles of the User being checked for access
	 * @param path
	 *       the File, URL, Object, etc. being checked for access
	 * 
	 * @return 
	 *       the rule stating whether to allow or deny access
	 * 
	 */
	private Rule searchForRule(Map map, Set roles, String path) {
		String canonical = null;
		try {
		    canonical = ESAPI.encoder().canonicalize(path);
		} catch (EncodingException e) {
		    logger.warning( Logger.SECURITY, false, "Failed to canonicalize input: " + path );
		}
		
		String part = canonical;
        if ( part == null ) {
            part = "";
        }
        
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
	 * Search for rule. Searches the specified access map to see if any of the roles specified have 
	 * access to perform the specified action on the specified Class.
	 * 
	 * @param map
	 *      the map containing access rules
	 * @param roles
	 *      the roles used to determine access level
	 * @param clazz
	 *      the Class being requested for access
	 * @param action
	 * 		the action the User has asked to perform
	 * 
	 * @return 
	 * 		the rule that allows the specified roles access to perform the requested action on the specified Class, or null if access is not granted
	 * 
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
	 * Return true if there is overlap between the two sets.  This method merely checks to see if 
	 * ruleRoles contains any of the roles listed in userRoles.
	 * 
	 * @param ruleRoles
	 *      the rule roles
	 * @param userRoles
	 *      the user roles
	 * 
	 * @return 
	 * 		true, if any roles exist in both Sets.  False otherwise.
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
	 * This method merely checks to see if ruleActions contains the action requested.
	 * 
	 * @param ruleActions
	 *      actions listed for a rule
	 * @param action
	 *      the action requested that will be searched for in ruleActions
	 * 
	 * @return 
	 * 		true, if any action exists in ruleActions.  False otherwise.
	 */
	private boolean overlap( List ruleActions, String action){
		if( ruleActions.contains(action) )
			return true;
		return false;
	}
		
	/**
	 * Checks that the roles passed in contain only letters, numbers, and underscores.  Also checks that
	 * roles are no more than 10 characters long.  If a role does not pass validation, it is not included in the 
	 * list of roles returned by this method.  A log warning is also generated for any invalid roles.
	 * 
	 * @param roles
	 * 		roles to validate according to criteria started above
	 * @return
	 * 		a List of roles that are valid according to the criteria stated above.
	 * 
	 */
	private List validateRoles(List roles){
		List ret = new ArrayList();	
		for(int x = 0; x < roles.size(); x++){
			String canonical = "";
			try {
				canonical = ESAPI.encoder().canonicalize(((String)roles.get(x)).trim());
			} catch (EncodingException e) {
				logger.warning( Logger.SECURITY, false, "Failed to canonicalize role " + ((String)roles.get(x)).trim(), e );
			}
			if(!ESAPI.validator().isValidInput("Validating user roles in FileBasedAccessController",canonical,"^[a-zA-Z0-9_]{0,10}$" ,200, false))
				logger.warning( Logger.SECURITY, false, "Role: " + ((String)roles.get(x)).trim() + " is invalid, so was not added to the list of roles for this Rule.");
			
			else 
				ret.add(canonical.trim());
		}
		return ret;
	}
	
	/**
	 * Loads access rules by storing them in a hashmap.  This method begins reading the File specified by
	 * the ruleset parameter, ignoring any lines that begin with '#' characters as comments.  Sections of the access rules file
	 * are split by the pipe character ('|').  The method loads all paths, replacing '\' characters with '/' for uniformity then loads
	 * the list of comma separated roles. The roles are validated to be sure they are within a 
	 * length and character set, specified in the validateRoles(String) method.  Then the permissions are stored for each item in the rules list.
	 * If the word "allow" appears on the line, the specified roles are granted access to the data - otherwise, they will be denied access.
	 * 
	 * Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored. 
	 *  
	 * @param ruleset
	 *      the name of the data that contains access rules
	 * 
	 * @return 
	 * 		a hash map containing the ruleset
	 */
	private Map loadRules(String ruleset) {
		Map map = new HashMap();
		InputStream is = null;
		try {
			is = ESAPI.securityConfiguration().getResourceStream(ruleset);
			String line = "";
			while ((line = ESAPI.validator().safeReadLine(is, 500)) != null) {
				if (line.length() > 0 && line.charAt(0) != '#') {
					Rule rule = new Rule();
					String[] parts = line.split("\\|");
					// fix Windows paths
					rule.path = parts[0].trim().replaceAll("\\\\", "/");
					
					List roles = commaSplit(parts[1].trim().toLowerCase());
					roles = validateRoles(roles);
					for(int x = 0; x < roles.size(); x++)
						rule.roles.add(((String)roles.get(x)).trim());
					
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
	 * Loads access rules by storing them in a hashmap.  This method begins reading the File specified by
	 * the ruleset parameter, ignoring any lines that begin with '#' characters as comments.  Sections of the access rules file
	 * are split by the pipe character ('|').  The method then loads all Classes, loads the list of comma separated roles, then the list of comma separated actions.  
	 * The roles are validated to be sure they are within a length and character set, specified in the validateRoles(String) method.  
	 * 
	 * Each path may only appear once in the access rules file.  Any entry, after the first, containing the same path will be logged and ignored. 
	 *  
	 * @param ruleset
	 *      the name of the data that contains access rules
	 * 
	 * @return 
	 * 		a hash map containing the ruleset
	 */
	private Map loadDataRules(String ruleset) {
		Map map = new HashMap();
		InputStream is = null;

		try {
			is = ESAPI.securityConfiguration().getResourceStream(ruleset);
			String line = "";
			while ((line = ESAPI.validator().safeReadLine(is, 500)) != null) {
				if (line.length() > 0 && line.charAt(0) != '#') {
					Rule rule = new Rule();
					String[] parts = line.split("\\|");
					rule.clazz = Class.forName(parts[0].trim());
					
					List roles = commaSplit(parts[1].trim().toLowerCase());
					roles = validateRoles(roles);
					for(int x = 0; x < roles.size(); x++)
						rule.roles.add(((String)roles.get(x)).trim());
					
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

	/**
	 * This method splits a String by the ',' and returns the result as a List.
	 * 
	 * @param input
	 * 		the String to split by ','
	 * @return
	 * 		a List where each entry was on either side of a ',' in the original String
	 */
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

		/**
	     * {@inheritDoc}
		 */
		public String toString() {
			return "URL:" + path + " | " + roles + " | " + (allow ? "allow" : "deny");
		}
	}
}
