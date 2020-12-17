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

import org.owasp.esapi.*;
import org.owasp.esapi.errors.*;

import java.io.*;
import java.util.*;

/**
 * Reference implementation of the Authenticator interface. This reference implementation is intended to be
 * an <b>EXAMPLE</b> only and is not really suitable for enterprise-wide applications. It is backed by a simple unsorted
 * text file that contains serialized information about users and it uses a relative weak password hashing algorithm.
 * (For further details, see the "See Also" section, below.)
 * <p>
 * Many organizations will want to create their own implementation of the methods provided in the
 * {@code Authenticator} interface backed by their own user repository as this reference implementation
 * is not very scalable. This reference implementation captures information about users in a simple text file
 * format that contains user information separated by the pipe "|" character.
 * <p/>
 * <p>Here's an example of a single line from the users.txt file:<p/>
 * <p>
 * <PRE>
 * account id | account name | hashed password | roles | lockout | status | old password hashes | last
 * hostname | last change | last login | last failed | expiration | failed
 * ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * 1203123710837 | mitch | 44k/NAzQUlrCq9musTGGkcMNmdzEGJ8w8qZTLzpxLuQ= | admin,user | unlocked | enabled |
 * u10dW4vTo3ZkoM5xP+blayWCz7KdPKyKUojOn9GJobg= | 192.168.1.255 | 1187201000926 | 1187200991568 | 1187200605330 |
 * 2187200605330 | 1
 * </PRE>
 * <p/>
 *
 * @author <a href="mailto:jeff.williams@aspectsecurity.com?subject=ESAPI question">Jeff Williams</a> at <a href="http://www.aspectsecurity.com">Aspect Security</a>
 * @author Chris Schmidt (chrisisbeef .at. gmail.com) <a href="http://www.digital-ritual.com">Digital Ritual Software</a>
 * @see org.owasp.esapi.Authenticator
 * @see #hashPassword(String password, String accountName)
 * @see <a href="https://github.com/ESAPI/esapi-java-legacy/issues/233" target="_blank" rel="noopener">GitHub Issue #233: Weak password storage</a>
 * @since June 1, 2007
 */
public class FileBasedAuthenticator extends AbstractAuthenticator {

    private static volatile Authenticator singletonInstance;

    public static Authenticator getInstance()
    {
        if ( singletonInstance == null ) {
            synchronized ( FileBasedAuthenticator.class ) {
                if ( singletonInstance == null ) {
                    singletonInstance = new FileBasedAuthenticator();
                }
            }
        }
        return singletonInstance;
    }

    /**
     * The logger.
     */
    private final Logger logger = ESAPI.getLogger("Authenticator");

    /**
     * The file that contains the user db
     */
    private File userDB = null;

    /**
     * How frequently to check the user db for external modifications
     */
    private long checkInterval = 60 * 1000;

    /**
     * The last modified time we saw on the user db.
     */
    private long lastModified = 0;

    /**
     * The last time we checked if the user db had been modified externally
     */
    private long lastChecked = 0;

    private static final int MAX_ACCOUNT_NAME_LENGTH = 250;

    /**
     * Fail safe main program to add or update an account in an emergency.
     * <p/>
     * Warning: this method does not perform the level of validation and checks
     * generally required in ESAPI, and can therefore be used to create a username and password that do not comply
     * with the username and password strength requirements.
     * <p/>
     * Example: Use this to add the alice account with the admin role to the users file:
     * <PRE>
     * <p/>
     * java -Dorg.owasp.esapi.resources="/path/resources" -classpath esapi.jar org.owasp.esapi.Authenticator alice password admin
     * <p/>
     * </PRE>
     *
     * @param args the arguments (username, password, role)
     * @throws Exception the exception
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Usage: Authenticator accountname password role");
            return;
        }
        FileBasedAuthenticator auth = new FileBasedAuthenticator();
        String accountName = args[0].toLowerCase();
        String password = args[1];
        String role = args[2];
        DefaultUser user = (DefaultUser) auth.getUser(args[0]);
        if (user == null) {
            user = new DefaultUser(accountName);
            String newHash = auth.hashPassword(password, accountName);
            auth.setHashedPassword(user, newHash);
            user.addRole(role);
            user.enable();
            user.unlock();
            auth.userMap.put(user.getAccountId(), user);
            System.out.println("New user created: " + accountName);
            auth.saveUsers();
            System.out.println("User account " + user.getAccountName() + " updated");
        } else {
            System.err.println("User account " + user.getAccountName() + " already exists!");
        }
    }

    /**
     * Add a hash to a User's hashed password list.  This method is used to store a user's old password hashes
     * to be sure that any new passwords are not too similar to old passwords.
     *
     * @param user the user to associate with the new hash
     * @param hash the hash to store in the user's password hash list
     */
    private void setHashedPassword(User user, String hash) {
        List<String> hashes = getAllHashedPasswords(user, true);
        hashes.add(0, hash);
        if (hashes.size() > ESAPI.securityConfiguration().getMaxOldPasswordHashes()) {
            hashes.remove(hashes.size() - 1);
        }
        logger.info(Logger.SECURITY_SUCCESS, "New hashed password stored for " + user.getAccountName());
    }

    /**
     * Return the specified User's current hashed password.
     *
     * @param user this User's current hashed password will be returned
     * @return the specified User's current hashed password
     */
    String getHashedPassword(User user) {
        List hashes = getAllHashedPasswords(user, false);
        return (String) hashes.get(0);
    }

    /**
     * Set the specified User's old password hashes.  This will not set the User's current password hash.
     *
     * @param user      the User whose old password hashes will be set
     * @param oldHashes a list of the User's old password hashes
     */
    void setOldPasswordHashes(User user, List<String> oldHashes) {
        List<String> hashes = getAllHashedPasswords(user, true);
        if (hashes.size() > 1) {
            hashes.removeAll(hashes.subList(1, hashes.size()));
        }
        hashes.addAll(oldHashes);
    }

    /**
     * Returns all of the specified User's hashed passwords.  If the User's list of passwords is null,
     * and create is set to true, an empty password list will be associated with the specified User
     * and then returned. If the User's password map is null and create is set to false, an exception
     * will be thrown.
     *
     * @param user   the User whose old hashes should be returned
     * @param create true - if no password list is associated with this user, create one
     *               false - if no password list is associated with this user, do not create one
     * @return a List containing all of the specified User's password hashes
     */
    List<String> getAllHashedPasswords(User user, boolean create) {
        List<String> hashes = passwordMap.get(user);
        if (hashes != null) {
            return hashes;
        }
        if (create) {
            hashes = new ArrayList<String>();
            passwordMap.put(user, hashes);
            return hashes;
        }
        throw new RuntimeException("No hashes found for " + user.getAccountName() + ". Is User.hashcode() and equals() implemented correctly?");
    }

    /**
     * Get a List of the specified User's old password hashes.  This will not return the User's current
     * password hash.
     *
     * @param user he user whose old password hashes should be returned
     * @return the specified User's old password hashes
     */
    List<String> getOldPasswordHashes(User user) {
        List<String> hashes = getAllHashedPasswords(user, false);
        if (hashes.size() > 1) {
            return Collections.unmodifiableList(hashes.subList(1, hashes.size()));
        }
        return Collections.emptyList();
    }

    /**
     * The user map.
     */
    private Map<Long, User> userMap = new HashMap<Long, User>();

    // Map<User, List<String>>, where the strings are password hashes, with the current hash in entry 0
    private Map<User, List<String>> passwordMap = new Hashtable<User, List<String>>();



    /**
     *
     */
    private FileBasedAuthenticator() {
    	super();
    }


    /**
     * {@inheritDoc}
     */
    public synchronized User createUser(String accountName, String password1, String password2) throws AuthenticationException {
        loadUsersIfNecessary();
        if (accountName == null) {
            throw new AuthenticationAccountsException("Account creation failed", "Attempt to create user with null accountName");
        }
        if (getUser(accountName) != null) {
            throw new AuthenticationAccountsException("Account creation failed", "Duplicate user creation denied for " + accountName);
        }

        verifyAccountNameStrength(accountName);

        if (password1 == null) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account " + accountName + " with a null password");
        }
        
        DefaultUser user = new DefaultUser(accountName);
        
        verifyPasswordStrength(null, password1, user);

        if (!password1.equals(password2)) {
            throw new AuthenticationCredentialsException("Passwords do not match", "Passwords for " + accountName + " do not match");
        }

        try {
            setHashedPassword(user, hashPassword(password1, accountName));
        } catch (EncryptionException ee) {
            throw new AuthenticationException("Internal error", "Error hashing password for " + accountName, ee);
        }
        userMap.put(user.getAccountId(), user);
        logger.info(Logger.SECURITY_SUCCESS, "New user created: " + accountName);
        saveUsers();
        return user;
    }

    /**
     * {@inheritDoc}
     */
    public String generateStrongPassword() {
        return generateStrongPassword("");
    }

    /**
     * Generate a strong password that is not similar to the specified old password.
     *
     * @param oldPassword the password to be compared to the new password for similarity
     * @return a new strong password that is dissimilar to the specified old password
     */
    private String generateStrongPassword(String oldPassword) {
        Randomizer r = ESAPI.randomizer();
        int letters = r.getRandomInteger(4, 6);  // inclusive, exclusive
        int digits = 7 - letters;
        String passLetters = r.getRandomString(letters, EncoderConstants.CHAR_PASSWORD_LETTERS);
        String passDigits = r.getRandomString(digits, EncoderConstants.CHAR_PASSWORD_DIGITS);
        String passSpecial = r.getRandomString(1, EncoderConstants.CHAR_PASSWORD_SPECIALS);
        String newPassword = passLetters + passSpecial + passDigits;
        if (StringUtilities.getLevenshteinDistance(oldPassword, newPassword) > 5) {
            return newPassword;
        }
        return generateStrongPassword(oldPassword);
    }

    /**
     * {@inheritDoc}
     */
    public void changePassword(User user, String currentPassword,
                               String newPassword, String newPassword2)
            throws AuthenticationException {
        String accountName = user.getAccountName();
        try {
            String currentHash = getHashedPassword(user);
            String verifyHash = hashPassword(currentPassword, accountName);
            if (!currentHash.equals(verifyHash)) {
                throw new AuthenticationCredentialsException("Password change failed", "Authentication failed for password change on user: " + accountName);
            }
            if (newPassword == null || newPassword2 == null || !newPassword.equals(newPassword2)) {
                throw new AuthenticationCredentialsException("Password change failed", "Passwords do not match for password change on user: " + accountName);
            }
            verifyPasswordStrength(currentPassword, newPassword, user);
            user.setLastPasswordChangeTime(new Date());
            String newHash = hashPassword(newPassword, accountName);
            if (getOldPasswordHashes(user).contains(newHash)) {
                throw new AuthenticationCredentialsException("Password change failed", "Password change matches a recent password for user: " + accountName);
            }
            setHashedPassword(user, newHash);
            logger.info(Logger.SECURITY_SUCCESS, "Password changed for user: " + accountName);
            // jtm - 11/2/2010 - added to resolve http://code.google.com/p/owasp-esapi-java/issues/detail?id=13
            saveUsers();
        } catch (EncryptionException ee) {
            throw new AuthenticationException("Password change failed", "Encryption exception changing password for " + accountName, ee);
        }
    }

    /**
     * {@inheritDoc}
     */
    public boolean verifyPassword(User user, String password) {
        String accountName = user.getAccountName();
        try {
            String hash = hashPassword(password, accountName);
            String currentHash = getHashedPassword(user);
            if (hash.equals(currentHash)) {
                user.setLastLoginTime(new Date());
                ((DefaultUser) user).setFailedLoginCount(0);
                logger.info(Logger.SECURITY_SUCCESS, "Password verified for " + accountName);
                return true;
            }
        } catch (EncryptionException e) {
            logger.fatal(Logger.SECURITY_FAILURE, "Encryption error verifying password for " + accountName);
        }
        logger.fatal(Logger.SECURITY_FAILURE, "Password verification failed for " + accountName);
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public String generateStrongPassword(User user, String oldPassword) {
        String newPassword = generateStrongPassword(oldPassword);
        if (newPassword != null) {
            logger.info(Logger.SECURITY_SUCCESS, "Generated strong password for " + user.getAccountName());
        }
        return newPassword;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized User getUser(long accountId) {
        if (accountId == 0) {
            return User.ANONYMOUS;
        }
        loadUsersIfNecessary();
        return userMap.get(accountId);
    }

    /**
     * {@inheritDoc}
     */
    public synchronized User getUser(String accountName) {
        if (accountName == null) {
            return User.ANONYMOUS;
        }
        loadUsersIfNecessary();
        for (User u : userMap.values()) {
            if (u.getAccountName().equalsIgnoreCase(accountName)) {
                return u;
            }
        }
        return null;
    }

 

    /**
     * {@inheritDoc}
     */
    public synchronized Set getUserNames() {
        loadUsersIfNecessary();
        HashSet<String> results = new HashSet<String>();
        for (User u : userMap.values()) {
            results.add(u.getAccountName());
        }
        return results;
    }

    /**
     * {@inheritDoc}
     *
     * <b>WARNING:</b> There are several weaknesses in this method:
     * <ol>
     * <li>The salt should really be a randomly generated salt, typically at
     * least 64-bits, but in this method, the {@code accountName} parameter is
     * used as the salt.</li>
     * <li>This salt is then combined with the <b>ESAPI.properties</b> file's
     * {@code Encryptor.MasterSalt}, meaning that if that property is changed,
     * all previously stored passwords become invalid and need to be reset.</li>
     * <li>Only 1024 iterations of the hash algorithm (SHA-512) are made. While that
     * may have been fine in 2007, it is no longer considered sufficient.</li>
     * </ol>
     *
     * @throws EncryptionException
     */
    public String hashPassword(String password, String accountName) throws EncryptionException {
        // Here is but one weakness: This salt should ideally be a _random_ salt,
        // at least 64 bits in length. Unfortunately, if anyone is actually using
        // this method in a production application (let's hope not) fixing this
        // now will those application's previously stored passwords. See this
        // GitHub issue comment for further details:
        //    https://github.com/ESAPI/esapi-java-legacy/issues/233#issuecomment-450401400
        String salt = accountName.toLowerCase();
        //
        // Other weaknesses are that only 1024 iterations of the hash algorithm
        // (SHA-512) is used and the final hash is tied to the Encryptor.MasterSalt
        // so if that is ever changed, all users passwords must be reset.
        return ESAPI.encryptor().hash(password, salt);
    }

    /**
     * Load users if they haven't been loaded in a while.
     */
    protected void loadUsersIfNecessary() {
        if (userDB == null) {
            userDB = ESAPI.securityConfiguration().getResourceFile("users.txt");
        }
        if (userDB == null) {
            userDB = new File(System.getProperty("user.home") + "/.esapi", "users.txt");
            try {
                if (!userDB.createNewFile()) throw new IOException("Unable to create the user file");
                logger.warning(Logger.SECURITY_SUCCESS, "Created " + userDB.getAbsolutePath());
            } catch (IOException e) {
                logger.fatal(Logger.SECURITY_FAILURE, "Could not create " + userDB.getAbsolutePath(), e);
            }
        }

        // We only check at most every checkInterval milliseconds
        long now = System.currentTimeMillis();
        if (now - lastChecked < checkInterval) {
            return;
        }
        lastChecked = now;

        if (lastModified == userDB.lastModified()) {
            return;
        }
        loadUsersImmediately();
    }

    // file was touched so reload it
    /**
     *
     */
    protected void loadUsersImmediately() {
        synchronized (this) {
            logger.trace(Logger.SECURITY_SUCCESS, "Loading users from " + userDB.getAbsolutePath(), null);

            BufferedReader reader = null;
            try {
                HashMap<Long, User> map = new HashMap<Long, User>();
                reader = new BufferedReader(new FileReader(userDB));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.length() > 0 && line.charAt(0) != '#') {
                        DefaultUser user = createUser(line);
                        if (map.containsKey(new Long(user.getAccountId()))) {
                            logger.fatal(Logger.SECURITY_FAILURE, "Problem in user file. Skipping duplicate user: " + user, null);
                        }
                        map.put(user.getAccountId(), user);
                    }
                }
                userMap = map;
                this.lastModified = System.currentTimeMillis();
                logger.trace(Logger.SECURITY_SUCCESS, "User file reloaded: " + map.size(), null);
            } catch (Exception e) {
                logger.fatal(Logger.SECURITY_FAILURE, "Failure loading user file: " + userDB.getAbsolutePath(), e);
            } finally {
                try {
                    if (reader != null) {
                        reader.close();
                    }
                } catch (IOException e) {
                    logger.fatal(Logger.SECURITY_FAILURE, "Failure closing user file: " + userDB.getAbsolutePath(), e);
                }
            }
        }
    }

    /**
     * Create a new user with all attributes from a String.  The format is:
     * accountId | accountName | password | roles (comma separated) | unlocked | enabled | old password hashes (comma separated) | last host address | last password change time | last long time | last failed login time | expiration time | failed login count
     * This method verifies the account name and password strength, creates a new CSRF token, then returns the newly created user.
     *
     * @param line parameters to set as attributes for the new User.
     * @return the newly created User
     * @throws AuthenticationException
     */
    private DefaultUser createUser(String line) throws AuthenticationException {
        String[] parts = line.split(" *\\| *");
        String accountIdString = parts[0];
        long accountId = Long.parseLong(accountIdString);
        String accountName = parts[1];

        verifyAccountNameStrength(accountName);
        DefaultUser user = new DefaultUser(accountName);
        user.accountId = accountId;

        String password = parts[2];
        verifyPasswordStrength(null, password, user);
        setHashedPassword(user, password);

        String[] roles = parts[3].toLowerCase().split(" *, *");
        for (String role : roles) {
            if (!"".equals(role)) {
                user.addRole(role);
            }
        }
        if (!"unlocked".equalsIgnoreCase(parts[4])) {
            user.lock();
        }
        if ("enabled".equalsIgnoreCase(parts[5])) {
            user.enable();
        } else {
            user.disable();
        }

        // generate a new csrf token
        user.resetCSRFToken();

        setOldPasswordHashes(user, Arrays.asList(parts[6].split(" *, *")));
        user.setLastHostAddress("null".equals(parts[7]) ? null : parts[7]);
        user.setLastPasswordChangeTime(new Date(Long.parseLong(parts[8])));
        user.setLastLoginTime(new Date(Long.parseLong(parts[9])));
        user.setLastFailedLoginTime(new Date(Long.parseLong(parts[10])));
        user.setExpirationTime(new Date(Long.parseLong(parts[11])));
        user.setFailedLoginCount(Integer.parseInt(parts[12]));
        return user;
    }

    /**
     * {@inheritDoc}
     */
    public synchronized void removeUser(String accountName) throws AuthenticationException {
        loadUsersIfNecessary();
        User user = getUser(accountName);
        if (user == null) {
            throw new AuthenticationAccountsException("Remove user failed", "Can't remove invalid accountName " + accountName);
        }
        userMap.remove(user.getAccountId());
        logger.info(Logger.SECURITY_SUCCESS, "Removing user " + user.getAccountName());
        passwordMap.remove(user);
        saveUsers();
    }

    /**
     * Saves the user database to the file system. In this implementation you must call save to commit any changes to
     * the user file. Otherwise changes will be lost when the program ends.
     *
     * @throws AuthenticationException if the user file could not be written
     */
    public synchronized void saveUsers() throws AuthenticationException {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(new FileWriter(userDB));
            writer.println("# This is the user file associated with the ESAPI library from http://www.owasp.org");
            writer.println("# accountId | accountName | hashedPassword | roles | locked | enabled | csrfToken | oldPasswordHashes | lastPasswordChangeTime | lastLoginTime | lastFailedLoginTime | expirationTime | failedLoginCount");
            writer.println();
            saveUsers(writer);
            writer.flush();
            logger.info(Logger.SECURITY_SUCCESS, "User file written to disk");
        } catch (IOException e) {
            logger.fatal(Logger.SECURITY_FAILURE, "Problem saving user file " + userDB.getAbsolutePath(), e);
            throw new AuthenticationException("Internal Error", "Problem saving user file " + userDB.getAbsolutePath(), e);
        } finally {
            if (writer != null) {
                writer.close();
                lastModified = userDB.lastModified();
                lastChecked = lastModified;
            }
        }
    }

    /**
     * Save users.
     *
     * @param writer the print writer to use for saving
     */
    protected synchronized void saveUsers(PrintWriter writer) throws AuthenticationCredentialsException {
        for (Object o : getUserNames()) {
            String accountName = (String) o;
            DefaultUser u = (DefaultUser) getUser(accountName);
            if (u != null && !u.isAnonymous()) {
                writer.println(save(u));
            } else {
                throw new AuthenticationCredentialsException("Problem saving user", "Skipping save of user " + accountName);
            }
        }
    }

    /**
     * Save.
     *
     * @param user the User to save
     * @return a line containing properly formatted information to save regarding the user
     */
    private String save(DefaultUser user) {
        StringBuilder sb = new StringBuilder();
        sb.append(user.getAccountId());
        sb.append(" | ");
        sb.append(user.getAccountName());
        sb.append(" | ");
        sb.append(getHashedPassword(user));
        sb.append(" | ");
        sb.append(dump(user.getRoles()));
        sb.append(" | ");
        sb.append(user.isLocked() ? "locked" : "unlocked");
        sb.append(" | ");
        sb.append(user.isEnabled() ? "enabled" : "disabled");
        sb.append(" | ");
        sb.append(dump(getOldPasswordHashes(user)));
        sb.append(" | ");
        sb.append(user.getLastHostAddress());
        sb.append(" | ");
        sb.append(user.getLastPasswordChangeTime().getTime());
        sb.append(" | ");
        sb.append(user.getLastLoginTime().getTime());
        sb.append(" | ");
        sb.append(user.getLastFailedLoginTime().getTime());
        sb.append(" | ");
        sb.append(user.getExpirationTime().getTime());
        sb.append(" | ");
        sb.append(user.getFailedLoginCount());
        return sb.toString();
    }

    /**
     * Dump a collection as a comma-separated list.
     *
     * @param c the collection to convert to a comma separated list
     * @return a comma separated list containing the values in c
     */
    private String dump(Collection<String> c) {
        StringBuilder sb = new StringBuilder();
        for (String s : c) {
            sb.append(s).append(",");
        }
        if ( c.size() > 0) {
        	return sb.toString().substring(0, sb.length() - 1);
        }
        return "";
        
    }

    /**
     * {@inheritDoc}
     * <p/>
     * This implementation simply verifies that account names are at least 5 characters long. This helps to defeat a
     * brute force attack, however the real strength comes from the name length and complexity.
     *
     * @param newAccountName
     */
    public void verifyAccountNameStrength(String newAccountName) throws AuthenticationException {
        if (newAccountName == null) {
            throw new AuthenticationCredentialsException("Invalid account name", "Attempt to create account with a null account name");
        }
        if (!ESAPI.validator().isValidInput("verifyAccountNameStrength", newAccountName, "AccountName", MAX_ACCOUNT_NAME_LENGTH, false)) {
            throw new AuthenticationCredentialsException("Invalid account name", "New account name is not valid: " + newAccountName);
        }
    }

    /**
     * {@inheritDoc}
     * <p/>
     * This implementation checks: - for any 3 character substrings of the old password - for use of a length *
     * character sets > 16 (where character sets are upper, lower, digit, and special
     * jtm - 11/16/2010 - added check to verify pw != username (fix for http://code.google.com/p/owasp-esapi-java/issues/detail?id=108)
     */
    public void verifyPasswordStrength(String oldPassword, String newPassword, User user) throws AuthenticationException {
        if (newPassword == null) {
            throw new AuthenticationCredentialsException("Invalid password", "New password cannot be null");
        }

        // can't change to a password that contains any 3 character substring of old password
        if (oldPassword != null) {
            int length = oldPassword.length();
            for (int i = 0; i < length - 2; i++) {
                String sub = oldPassword.substring(i, i + 3);
                if (newPassword.indexOf(sub) > -1) {
                    throw new AuthenticationCredentialsException("Invalid password", "New password cannot contain pieces of old password");
                }
            }
        }

        // new password must have enough character sets and length
        int charsets = 0;
        for (int i = 0; i < newPassword.length(); i++) {
            if (Arrays.binarySearch(EncoderConstants.CHAR_LOWERS, newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (int i = 0; i < newPassword.length(); i++) {
            if (Arrays.binarySearch(EncoderConstants.CHAR_UPPERS, newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (int i = 0; i < newPassword.length(); i++) {
            if (Arrays.binarySearch(EncoderConstants.CHAR_DIGITS, newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }
        for (int i = 0; i < newPassword.length(); i++) {
            if (Arrays.binarySearch(EncoderConstants.CHAR_SPECIALS, newPassword.charAt(i)) >= 0) {
                charsets++;
                break;
            }
        }

        // calculate and verify password strength
        int strength = newPassword.length() * charsets;
        if (strength < 16) {
            throw new AuthenticationCredentialsException("Invalid password", "New password is not long and complex enough");
        }
        
        String accountName = user.getAccountName();
        
        //jtm - 11/3/2010 - fix for bug http://code.google.com/p/owasp-esapi-java/issues/detail?id=108
        if (accountName.equalsIgnoreCase(newPassword)) {
        	//password can't be account name
        	throw new AuthenticationCredentialsException("Invalid password", "Password matches account name, irrespective of case");
        }
    }

}
