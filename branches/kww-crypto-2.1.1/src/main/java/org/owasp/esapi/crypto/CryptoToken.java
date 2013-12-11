/**
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2010 - The OWASP Foundation
 * 
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 * 
 * @created 2010
 */
package org.owasp.esapi.crypto;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encryptor;
import org.owasp.esapi.Logger;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.EncryptionException;
import org.owasp.esapi.errors.ValidationException;

///// IMPORTANT NOTE: Never print / log attribute *values* as they
/////                 may be sensitive. Also, do not log the CryptoToken
/////				  itself as it generally is used as an authentication token.

// OPEN ISSUE: Assertions vs. IllegalArgumentException must be resolved. I prefer
//             assertions for preconditions, which is more in line with Design-by-Contract
//             and Eiffel. There are a few places where assertions are not appropriate
//             because if they are not disabled (they are not by default), they could cause
//             incorrect behavior (e.g., setting the expiration time to something in the
//             past, etc.)

/**
 * Compute a cryptographically secure, encrypted token containing
 * optional name/value pairs. The cryptographic token is computed
 * like this:
 * <pre>
 *     username;expiration_time;[&lt;attr1&gt;;&lt;attr2&gt;;...;&lt;attrN&gt;;]
 * </pre>
 * where
 * <i>username</i> is a user account name. Defaults to &lt;anonymous&gt; if
 * not set and it is always converted to lower case as per the rules of the
 * default locale. (Note this lower case conversion is consistent with the
 * default reference implementation of ESAPI's {@code User} interface.)
 * <br>
 * <i>expiration_time</i> is time (in milliseconds) after which the encrypted
 * token is considered invalid (i.e., expired). The time is stored as
 * milliseconds since midnight, January 1, 1970 UTC, and optional attributes
 * <br>
 * &nbsp;&nbsp;<i>&lt;attr1&gt;</i>;<i>&lt;attr2&gt;</i>;...<i>&lt;attrN&gt;</i>;
 * <br>
 * are optional semicolon (';') separated name/value pairs, where each
 * name/value pair has the form:
 * <pre>
 *         name=[value]        (value may be empty, but not null)
 * </pre>
 * The attribute value may contain any value. However, values containing
 * either '=' or ';' will be quoted using '\'. Likewise, values containing '\'
 * will also be quoted using '\'. Hence if original name/value pair were
 *             name=ab=xy\;
 *         this would be represented as
 *             name=ab\=xy\\\;
 * To ensure things are "safe" (from a security perspective), attribute
 * <i>names</i> must conform the the Java regular expression
 * <pre>
 *          [A-Za-z0-9_\.-]+
 * </pre>
 * The attribute <i>value</i> on the other hand, may be any valid string. (That
 * is, the value is not checked, so beware!)
 * <p>
 * This entire semicolon-separated string is then encrypted via one of the 
 * {@code Encryptor.encrypt()} methods and then base64-encoded, serialized
 * IV + ciphertext + MAC representation as determined by
 * {@code CipherTextasPortableSerializedByteArray()} is used as the
 * resulting cryptographic token.
 * <p>
 * The attributes are sorted by attribute name and the attribute names
 * must be unique. There are some restrictions on the attribute names.
 * (See the {@link #setAttribute(String, String)} method for details.)
 *
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public class CryptoToken {
    /** Represents an anonymous user. */
    public static final String ANONYMOUS_USER = "<anonymous>";
    
    // Default expiration time
    private static final long DEFAULT_EXP_TIME = 5 * 60 * 1000;  // 5 min == 300 milliseconds
    private static final String DELIM = ";";                     // field delimiter
    private static final char DELIM_CHAR = ';';                  // field delim as a char
    private static final char QUOTE_CHAR = '\\';                 // char used to quote delimiters, '=' and itself.
    
        // OPEN ISSUE: Should we make these 2 regex's properties in ESAPI.properties???
    private static final String ATTR_NAME_REGEX = "[A-Za-z0-9_.-]+"; // One or more alphanumeric, underscore, periods, or hyphens.
    private static final String USERNAME_REGEX = "[a-z][a-z0-9_.@-]*";
    
    private static Logger logger = ESAPI.getLogger("CryptoToken");

    private String username = ANONYMOUS_USER;        // Default user name if not set. Always lower case.
    private long expirationTime = 0L;
        // This probably needed be sorted. A HashMap would do as well.
        // But this might make debugging a bit easier, so why not?
    private TreeMap<String, String> attributes = new TreeMap<String,String>();
    private transient SecretKey secretKey = null;
    private Pattern attrNameRegex = Pattern.compile(ATTR_NAME_REGEX);
    private Pattern userNameRegex = Pattern.compile(USERNAME_REGEX);
    
    /**
     * Create a cryptographic token using default secret key from the
     * <b>ESAPI.properties</b> property <b>Encryptor.MasterKey</b>. 
     */
    public CryptoToken() {
        secretKey = getDefaultSecretKey(
                            ESAPI.securityConfiguration().getEncryptionAlgorithm()
                        );
        long now = System.currentTimeMillis();
        expirationTime = now + DEFAULT_EXP_TIME;
    }

    // Create using specified SecretKey
    /**
     * Create a cryptographic token using specified {@code SecretKey}.
     * 
     * @param skey  The specified {@code SecretKey} to use to encrypt the token.
     */
    public CryptoToken(SecretKey skey) {
        if ( skey == null ) {
        	throw new IllegalArgumentException("SecretKey may not be null.");
        }
        secretKey = skey;
        long now = System.currentTimeMillis();
        expirationTime = now + DEFAULT_EXP_TIME;
    }

    /** 
     * Create using previously encrypted token encrypted with default secret
     * key from <b>ESAPI.properties</b>.
     * @param token A previously encrypted token returned by one of the
     *              {@code getToken()} or {@code updateToken()} methods. The
     *              token <i>must</i> have been previously encrypted using the
     *              using default secret key from the <b>ESAPI.properties</b>
     *              property <b>Encryptor.MasterKey</b>.
     * @throws EncryptionException  Thrown if they are any problems while decrypting
     *                              the token using the default secret key from
     *                              <b>ESAPI.properties</b> or if the decrypted
     *                              token is not properly formatted.
     */
    public CryptoToken(String token) throws EncryptionException {
    	if ( token == null ) {
    		throw new IllegalArgumentException("Token may not be null.");
    	}
        secretKey = getDefaultSecretKey(
                ESAPI.securityConfiguration().getEncryptionAlgorithm()
            );
        try {
            decryptToken(secretKey, token);
        } catch (EncodingException e) {
            throw new EncryptionException("Decryption of token failed. Token improperly encoded or encrypted with different key.",
                                          "Can't decrypt token because not correctly encoded or encrypted with different key.", e);
        }
    }

    /** 
     * Create cryptographic token using previously encrypted token that was
     * encrypted with specified secret key.
     * 
     * @param token A previously encrypted token returned by one of the
     *              {@code getToken()} or {@code updateToken()} methods.
     * @throws EncryptionException  Thrown if they are any problems while decrypting
     *                              the token using the default secret key from
     *                              <b>ESAPI.properties</b> or if the decrypted
     *                              token is not properly formatted.
     */
    // token is a previously encrypted token (i.e., CryptoToken.getToken())
    // with different SecretKey other than the one in ESAPI.properties
    public CryptoToken(SecretKey skey, String token) throws EncryptionException {
        if ( skey == null ) {
        	throw new IllegalArgumentException("SecretKey may not be null.");
        }
    	if ( token == null ) {
    		throw new IllegalArgumentException("Token may not be null.");
    	}
        secretKey = skey;
        try {
            decryptToken(secretKey, token);
        } catch (EncodingException e) {
            throw new EncryptionException("Decryption of token failed. Token improperly encoded or encrypted with different key.",
            							  "Can't decrypt token because not correctly encoded or encrypted with different key.", e);
        }
    }

    /**
     * Retrieve the user account name associated with this {@code CryptoToken}
     * object.
     * @return  The user account name. The string represented by
     *          {@link #ANONYMOUS_USER} is returned if
     *          {@link #setUserAccountName(String)} was never called.
     */
    public String getUserAccountName() {
        return ( (username != null) ? username : ANONYMOUS_USER );
    }
    
    /**
     * Set the user account name associated with this cryptographic token
     * object. The user account name is converted to lower case.
     * @param userAccountName   The user account name.
     * @throws ValidationException  Thrown if user account name is not valid, i.e.,
     *                              if it doesn't conform to the regular expression
     *                              given by "[a-z][a-z0-9_.@-]*". (Note that the
     *                              parameter {@code userAccountName} is first converted
     *                              to lower case before checked against the regular
     *                              expression.)
     */
    public void setUserAccountName(String userAccountName) throws ValidationException {
        if ( userAccountName == null || userAccountName.equals("") ) {
        	throw new IllegalArgumentException("User account name may not be null or empty.");
        }
        
        // Converting to lower case first allows a simpler regex. Also, generally user account
        // names (but not passwords) are case insensitive in many OSes.
        String userAcct = userAccountName.toLowerCase();
        
        // Check to make sure that attribute name is valid as per our regex.
        Matcher userNameChecker = userNameRegex.matcher(userAcct);
        if ( userNameChecker.matches() ) {
            username = userAcct;
        } else {
            throw new ValidationException("Invalid user account name encountered.",
                                          "User account name " + userAccountName +
                                              " does not match regex " +
                                              USERNAME_REGEX + " after conversion to lowercase.");
        }
    }

    /** Check if token has expired yet.
     * @return  True if token has expired; false otherwise.
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTime;
    }
    
    /**
     * Set expiration time to expire in 'interval' seconds (NOT milliseconds).
     * @param intervalSecs  Number of seconds in the future from current date/time
     *                  	to set expiration. Must be positive.
     */
    public void setExpiration(int intervalSecs) throws IllegalArgumentException
    {
        int intervalMillis = intervalSecs * 1000;   // Need to convert secs to millisec.
        
        // Don't want to use assertion here, because if they are disabled,
        // this would result in setting the expiration time prior to the
        // current time, hence it would already be expired.
        if ( intervalMillis <= 0) {
            throw new IllegalArgumentException("intervalSecs argument, converted to millisecs, must be > 0.");
        }
        // Check for arithmetic overflow here. In reality, this condition
        // should never happen, but we want to avoid it--even theoretically--
        // since otherwise, it could have security implications.
        long now = System.currentTimeMillis();
        preAdd(now, intervalMillis);
        expirationTime = now + intervalMillis;
    }
    
    /**
     * Set expiration time for a specific date/time.
     * @param expirationDate    The date/time at which the token will fail. Must
     *                          be after the current date/time.
     * @throws IllegalArgumentException Thrown if the parameter is null.
     */
    public void setExpiration(Date expirationDate) throws IllegalArgumentException
    {
        if ( expirationDate == null ) {
            throw new IllegalArgumentException("expirationDate may not be null.");
        }
        long curTime = System.currentTimeMillis();
        long expTime = expirationDate.getTime();
        if ( expTime <= curTime ) {
            throw new IllegalArgumentException("Expiration date must be after current date/time.");
        }        
        expirationTime = expTime;
    }
    
    /**
     * Return the expiration time in milliseconds since epoch time (midnight,
     * January 1, 1970 UTC).
     * @return  The current expiration time.
     */
    public long getExpiration() {
        assert expirationTime > 0L : "Programming error: Expiration time <= 0";
        return expirationTime;
    }
    
    /**
     * Return the expiration time as a {@code Date}.
     * @return The {@code Date} object representing the expiration time.
     */
    public Date getExpirationDate() {
        return new Date( getExpiration() );
    }

    /**
     * Set a name/value pair as an attribute.
     * @param name  The attribute name
     * @param value The attribute value
     * @throws ValidationException  Thrown if the attribute name is not properly
     *                              formed. That is, the attribute name does not
     *                              match the regular expression "[A-Za-z0-9_.-]+".
     */
    public void setAttribute(String name, String value) throws ValidationException {
        if ( name == null || name.length() == 0 ) {
            // CHECKME: Should this be an IllegalArgumentException instead? I
            // would prefer an assertion here and state this as a precondition
            // in the Javadoc.
            throw new ValidationException("Null or empty attribute NAME encountered",
                                          "Attribute NAMES may not be null or empty string.");
        }
        if ( value == null ) {
            // CHECKME: Should this be an IllegalArgumentException instead? I
            // would prefer an assertion here and state this as a precondition
            // in the Javadoc.
            throw new ValidationException("Null attribute VALUE encountered for attr name " + name,
                                          "Attribute VALUE may not be null; attr name: " + name);            
        }
        // NOTE: OTOH, it *is* VALID if the _value_ is empty! Null values cause too much trouble
        // to make it worth the effort of getting it to work consistently.

        // Check to make sure that attribute name is valid as per our regex.
        Matcher attrNameChecker = attrNameRegex.matcher(name);
        if ( attrNameChecker.matches() ) {
            attributes.put(name, value);
        } else {
            throw new ValidationException("Invalid attribute name encountered.",
                                          "Attribute name " + name + " does not match regex " +
                                          ATTR_NAME_REGEX);
        }
    }
    
    /**
     * Add the specified collection of attributes to the current attributes.
     * If there are duplicate attributes specified, they will replace any
     * existing ones.
     * 
     * @param attrs Name/value pairs of attributes to add or replace the existing
     *              attributes. Map must be non-null, but may be empty.
     * @throws ValidationException Thrown if one of the keys in the specified
     *                             parameter {@code attrs} is not a valid name.
     *                             That is, all attribute names must match the regular
     *                             expression ""[A-Za-z0-9_.-]+".
     * @see #setAttribute(String, String)
     */
    public void addAttributes(final Map<String, String> attrs) throws ValidationException {
        // CHECKME: Assertion vs. IllegalArgumentException
        if ( attrs == null ) {
        	throw new IllegalArgumentException("Attribute map may not be null.");
        }
        Set< Entry<String,String> > keyValueSet = attrs.entrySet();
        Iterator<Entry<String, String>> it = keyValueSet.iterator();
        while( it.hasNext() ) {
            Map.Entry<String,String> entry = it.next();
            String key = entry.getKey();
            String value = entry.getValue();
            setAttribute(key, value);
        }
        return;
    }
    
    /**
     * Retrieve the attribute with the specified name.
     * @param name  The attribute name.
     * @return  The value associated with the attribute name. If attribute is not
     *          set, then {@code null} is returned.
     */
    public String getAttribute(String name) {
        return attributes.get(name);
    }
    
    /**
     * Retrieve a {@code Map} that is a clone of all the attributes. A <i>copy</i>
     * is returned so that the attributes in {@code CrytpToken} are unaffected
     * by alterations made the returned {@code Map}. (Otherwise, multi-threaded code
     * could get trick.
     * 
     * @return  A {@code Map} of all the attributes.
     * @see #getAttribute(String)
     */
    @SuppressWarnings("unchecked")
    public Map<String, String> getAttributes() {
        // Unfortunately, this requires a cast, which requires us to supress warnings.
        return (Map<String, String>) attributes.clone();
    }
    
    /**
     * Removes all the attributes (if any) associated with this token. Note
     * that this does not clear / reset the user account name or expiration time.
     */
    public void clearAttributes() {
        attributes.clear();
    }

    /**
     * Return the new encrypted token as a base64-encoded string, encrypted with
     * the specified {@code SecretKey} which may be a different key than what the
     * token was originally encrypted with. E.g.,
     * <pre>
     *   Alice:
     *      SecretKey aliceSecretKey = ...; // Shared with Bob
     *      CryptoToken cryptoToken = new CryptoToken(skey1);
     *      cryptoToken.setUserAccountName("kwwall");
     *      cryptoToken.setAttribute("role", "admin");
     *      cryptoToken.setAttribute("state", "Ohio");
     *      String token = cryptoToken.getToken(); // Encrypted with skey1
     *      // send token to Bob ...
     *  --------------------------------------------------------------------
     *  Bob:
     *      ...
     *      SecretKey aliceSecretKey = ...  // Shared with Alice
     *      SecretKey bobSecretKey = ...;   // Shared with Carol
     *      CryptoToken cryptoToken = new CryptoToken(aliceSecretKey, tokenFromAlice);
     *      
     *      // Re-encrypt for Carol using my (Bob's) key...
     *      String tokenForCarol = cryptoToken.getToken(bobSecretKey);
     *      // send tokenForCarol to Carol ...
     *      // use token ourselves
     *  --------------------------------------------------------------------
     *  Carol:
     *      ...
     *      SecretKey bobSecretKey = ...;   // Shared with Bob.
     *      CryptoToken cryptoToken = new CryptoToken(bobSecretKey, tokenFromBob);
     *      if ( ! cryptoToken.isExpired() ) {
     *          String userName = cryptoToken.getUserAccountName();
     *          String roleName = cryptoToken.getAttribute("role");
     *          if ( roleName != null && roleName.equalsIgnoreCase("admin") ) {
     *              // grant admin access...
     *              ...
     *          }
     *      }
     *      ...
     * </pre>
     * @param skey  The specified key to (re)encrypt the token.
     * @return The newly encrypted token.
     */
    public String getToken(SecretKey skey) throws EncryptionException {
        return createEncryptedToken(skey);
    }
    
    /**
     * Update the (current) expiration time by adding the specified number of
     * seconds to it and then re-encrypting with the current {@code SecretKey}
     * that was used to construct this object.
     * 
     * @param additionalSecs    The additional number of seconds to add to the
     *                          current expiration time. This number must be
     *                          &gt;= 0 or otherwise an {@code IllegalArgumentException}
     *                          is thrown.
     * @return  The re-encrypted token with the updated expiration time is returned.
     * @throws  IllegalArgumentException    Thrown if parameter {@code additionalSecs}
     *                                      is less than 0.
     * @throws  EncryptionException         Thrown if the encryption fails.
     * @throws ValidationException          Thrown if the token will have already expired
     *                                      even after adding the specified number of
     *                                      additional seconds.
     * @throws  ArithmeticException         If additional seconds is large enough such
     *                                      that it would cause an arithmetic overflow
     *                                      with a long (the current expiration time)
     *                                      when added to the {@code additionalSecs}
     *                                      parameter.
     */
    public String updateToken(int additionalSecs) throws EncryptionException, ValidationException {
        if ( additionalSecs < 0) {
            throw new IllegalArgumentException("additionalSecs argument must be >= 0.");
        }
        
        // Avoid integer overflow. This could happen if one first calls
        // setExpiration(Date) with a date far into the future. We want
        // to avoid overflows as they might lead to security vulnerabilities.
        long curExpTime = getExpiration();
        preAdd(curExpTime, additionalSecs * 1000);
            // Note: Can't use setExpiration(int) here was this needs a
            //       'long'. Could convert to Date first, and use
            //       setExpiration(Date) but that hardly seems worth the trouble.
        expirationTime = curExpTime + (additionalSecs * 1000);
        
        if ( isExpired() ) {
            // Too bad there is no ProcrastinationException ;-)
            expirationTime = curExpTime;    // Restore the original value (which still may
                                            // be expired.
            throw new ValidationException("Token timed out.",
                    "Cryptographic token not increased to sufficient value to prevent timeout.");
            
        }
            // Don't change anything else (user acct name, attributes, skey, etc.)
        return getToken();
    }

    /**
     * Return the new encrypted token as a base64-encoded string, encrypted with
     * the specified {@code SecretKey} with which this object was constructed.
     * 
     * @return The newly encrypted token.
     * @see #getToken(SecretKey)
     */
    public String getToken() throws EncryptionException {
        return createEncryptedToken(secretKey);
    }
   
    // Create the actual encrypted token based on the specified SecretKey.
    // This method will ensure that the decrypted token always ends with an
    // unquoted delimiter.
    private String createEncryptedToken(SecretKey skey) throws EncryptionException {
        StringBuilder sb = new StringBuilder( getUserAccountName() + DELIM);
        // CHECKME: Should we check here to see if token has already expired
        //          and refuse to encrypt it (by throwing exception) if it has???
        //          If so, then updateToken() should also be revisited.
        sb.append( getExpiration() ).append( DELIM );
        sb.append( getQuotedAttributes() );
        
        Encryptor encryptor = ESAPI.encryptor();
        CipherText ct = encryptor.encrypt(skey, new PlainText( sb.toString() ) );
        String b64 =
            ESAPI.encoder().encodeForBase64(ct.asPortableSerializedByteArray(),
                                            false);
        return b64;
    }
    
    // Return a string of all the attributes, properly quoted. This is used in
    // creating the encrypted token. Note that this method ensures that the
    // quoted attribute string always ends with an (quoted) delimiter.
    private String getQuotedAttributes() {
        StringBuilder sb = new StringBuilder();
        Set< Entry<String,String> > keyValueSet = attributes.entrySet();
        Iterator<Entry<String, String>> it = keyValueSet.iterator();
        while( it.hasNext() ) {
            Map.Entry<String,String> entry = it.next();
            String key = entry.getKey();
            String value = entry.getValue();
            // Because attribute values may be confidential, we don't want to log them!
            logger.debug(Logger.EVENT_UNSPECIFIED, "   " + key + " -> <not shown>");
            sb.append(key + "=" + quoteAttributeValue( value ) + DELIM);
        }
        return sb.toString();
    }
    
    // Do NOT define a toString() method as there may be sensitive
    // information contained in the attribute names. If we absolutely
    // need this, then only return the username and expiration time, and
    // _maybe_ the attribute names, but not there values. And obviously,
    // we NEVER want to include the SecretKey should we decide to do this.
    /*
     * public String toString() { return null; }
     */
    
    
    // Quote any special characters in value.
    private static String quoteAttributeValue(String value) {
        assert value != null : "Program error: Value should not be null."; // Empty is OK.
        StringBuilder sb = new StringBuilder();
        char[] charArray = value.toCharArray();
        for( int i = 0; i < charArray.length; i++ ) {
            char c = charArray[i];
            if ( c == QUOTE_CHAR || c == '=' || c == DELIM_CHAR ) {
                sb.append(QUOTE_CHAR).append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    
    // Parse the possibly quoted value and return the unquoted value.
    private static String parseQuotedValue(String quotedValue) {
        StringBuilder sb = new StringBuilder();
        char[] charArray = quotedValue.toCharArray();
        for( int i = 0; i < charArray.length; i++ ) {
            char c = charArray[i];
            if ( c == QUOTE_CHAR ) {
                i++;    // Skip past quote character.
                sb.append( charArray[i] );
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    
    /*
     * Decrypt the encrypted token and parse it into the individual components.
     * The string should always end with a semicolon (;) even when there are
     * no attributes set.
     * <p>
     * Example of how quoted string might look:
     * <pre>
     *                            v              v  v            v     v
     *  kwwall;1291183520293;abc=x\=yx;xyz=;efg=a\;a\;;bbb=quotes\\tuff\;;
              |             |         |    |          |                  |
     *
     * </pre>
     */
    private void decryptToken(SecretKey skey, String b64token) throws EncryptionException, EncodingException {
        byte[] token = null;
        try {
            token = ESAPI.encoder().decodeFromBase64(b64token);
        } catch (IOException e) {
            // CHECKME: Not clear if we should log the actual token itself. It's encrypted,
            //          but could be arbitrarily long, especially since it is not valid
            //          encoding. OTOH, it may help debugging as sometimes it may be a simple
            //          case like someone failing to apply some other type of encoding
            //          consistently (e.g., URL encoding), in which case logging this should
            //          make this pretty obvious once a few of these are logged.
            throw new EncodingException("Invalid base64 encoding.",
                                          "Invalid base64 encoding. Encrypted token was: " + b64token);
        }
        CipherText ct = CipherText.fromPortableSerializedBytes(token);
        Encryptor encryptor = ESAPI.encryptor();
        PlainText pt = encryptor.decrypt(skey, ct);
        String str = pt.toString();
        assert str.endsWith(DELIM) : "Programming error: Expecting decrypted token to end with delim char, " + DELIM_CHAR;
        char[] charArray = str.toCharArray();
        int prevPos = -1;                // Position of previous unquoted delimiter.
        int fieldNo = 0;
        ArrayList<Object> fields = new ArrayList<Object>();
        int lastPos = charArray.length;
        for ( int curPos = 0; curPos < lastPos; curPos++ ) {
            boolean quoted = false;
            char curChar = charArray[curPos];
            if ( curChar == QUOTE_CHAR ) {
                // Found a case where we have quoted character. We need to skip
                // over this and set the current character to the next character.
                curPos++;
                if ( curChar != lastPos ) {
                    curChar = charArray[ curPos + 1 ];
                    quoted = true;
                } else {
                    // Last position will always be a delimiter character that
                    // should be treated as unquoted.
                    curChar = DELIM_CHAR;
                }
            }
            if ( curChar == DELIM_CHAR && !quoted ) {
                // We found an actual (unquoted) field delimiter.
                String record = str.substring(prevPos + 1, curPos);
                fields.add( record );
                fieldNo++;
                prevPos = curPos;
            } 
        }
        
        Object[] objArray = fields.toArray();
        assert fieldNo == objArray.length : "Program error: Mismatch of delimited field count.";
        logger.debug(Logger.EVENT_UNSPECIFIED, "Found " + objArray.length + " fields.");
        assert objArray.length >= 2 : "Missing mandatory fields from decrypted token (username &/or expiration time).";
        
        username = ((String)(objArray[0])).toLowerCase();
        String expTime = (String)objArray[1];
        expirationTime = Long.parseLong(expTime);
        if ( username == null ) {
        	throw new EncryptionException("Username null in decrypted token.",
        							      "Programming error? Decrypted token found username null.");
        }
        if ( expirationTime <= 0 ) {
        	throw new EncryptionException("Expiration time <= 0 in decrypted token.",
        								  "Programming error? Decrypted token found expirationTime <= 0.");
        }
        
        for( int i = 2; i < objArray.length; i++ ) {
            String nvpair = (String)objArray[i];
            int equalsAt = nvpair.indexOf("=");
            if ( equalsAt == -1 ) {
                throw new EncryptionException("Invalid attribute encountered in decrypted token.",
                        "Malformed attribute name/value pair (" + nvpair + ") found in decrypted token.");
            }
            String name = nvpair.substring(0, equalsAt);
            String quotedValue = nvpair.substring(equalsAt + 1);
            String value = parseQuotedValue( quotedValue );
            // Because attribute values may be confidential, we don't want to log them!
            logger.debug(Logger.EVENT_UNSPECIFIED, "Attribute[" + i + "]: name=" + name + ", value=<not shown>");

            // Check to make sure that attribute name is valid as per our regex.
            Matcher attrNameChecker = attrNameRegex.matcher(name);
            if ( attrNameChecker.matches() ) {
                attributes.put(name, value);
            } else {
                throw new EncryptionException("Invalid attribute name encountered in decrypted token.",
                                              "Invalid attribute name encountered in decrypted token; " +
                                              "attribute name " + name + " does not match regex " +
                                              ATTR_NAME_REGEX);
            }
            attributes.put(name, value);
        }
        return;
    }
    
    private SecretKey getDefaultSecretKey(String encryptAlgorithm) {
        if ( encryptAlgorithm == null ) {
        	throw new IllegalArgumentException("Encryption algorithm cannot be null.");
        }
        byte[] skey = ESAPI.securityConfiguration().getMasterKey();
        assert skey != null : "Can't obtain master key, Encryptor.MasterKey";
        assert skey.length >= 7 :
                        "Encryptor.MasterKey must be at least 7 bytes. " +
                        "Length is: " + skey.length + " bytes.";
        // Set up secretKeySpec for use for symmetric encryption and decryption,
        // and set up the public/private keys for asymmetric encryption /
        // decryption.
        return new SecretKeySpec(skey, encryptAlgorithm );
    }
    
    // Check precondition to see if addition of two operands will result in
    // arithmetic overflow. Note that the operands are of two different
    // integral types. I.e., check to see if:
    //      long result = leftLongValue + rightIntValue
    // would cause arithmetic overflow.
    // Note: We know that as we use it here, leftLongValue will always be > 0,
    //       so arithmetic underflow should never be possible, but we check for
    //       it anyhow.
    // Package level access to allow this to be used by other classes in this package.
    static final void preAdd(long leftLongValue, int rightIntValue) throws ArithmeticException {
        if ( rightIntValue > 0 && ( (leftLongValue + rightIntValue) < leftLongValue) ) {
            throw new ArithmeticException("Arithmetic overflow for addition.");
        }
        if ( rightIntValue < 0 && ( (leftLongValue + rightIntValue) > leftLongValue) ) {
            throw new ArithmeticException("Arithmetic underflow for addition.");
        }
    }

}
