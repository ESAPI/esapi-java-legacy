package org.owasp.esapi.reference.crypto;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Helper class to see if unlimited strength crypto is available. If it is
 * not, then symmetric encryption algorithms are restricted to 128-bit
 * key size or the encryption must provide key weakening or key escrow.
 * <p>
 * This program attempts to generate a 256-bit AES key and use it to do
 * to a simple encryption. If the encryption succeeds, the assumption is
 * that the JVM being used has the "unlimited" strength JCE jurisdiction
 * policy files installed.
 * </p><p>
 * We use this for JUnit tests. If unlimited strength crypto is not available,
 * we simply skip certain JUnit tests that would require it.
 */
public class CryptoPolicy {

    private static boolean checked = false;
    private static boolean unlimited = false;

    /**
     * Check to see if unlimited strength crypto is available.
     * There is an implicit assumption that the JCE jurisdiction policy
     * files are not going to be changing while this given JVM is running.
     *
     * @return True if we can provide keys longer than 128 bits.
     */
    public synchronized static boolean isUnlimitedStrengthCryptoAvailable()
    {
        if ( checked == false ) {
            unlimited = checkCrypto();
            checked = true;
        }
        return unlimited;
    }

    private static boolean checkCrypto()
    {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);   // Max sym key size is 128 unless unlimited
                                // strength jurisdiction policy files installed.
            SecretKey skey = keyGen.generateKey();
            byte[] raw = skey.getEncoded();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            
                // This usually will throw InvalidKeyException unless the
                // unlimited jurisdiction policy files are installed. However,
                // it can succeed even if it's not a provider chooses to use
                // an exemption mechanism such as key escrow, key recovery, or
                // key weakening for this cipher instead.
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            
                // Try the encryption on dummy string to make sure it works.
                // Not using padding so # bytes must be multiple of AES cipher
                // block size which is 16 bytes. Also, OK not to use UTF-8 here.
            @SuppressWarnings("unused")
            byte[] encrypted = cipher.doFinal("1234567890123456".getBytes());
            ExemptionMechanism em = cipher.getExemptionMechanism();
            if ( em != null ) {
                System.out.println("Cipher uses exemption mechanism " + em.getName());
                return false;   // This is actually an indeterminant case, but
                                // we can't bank on it at least for this
                                // (default) provider.
            }
        } catch( InvalidKeyException ikex ) {
            System.out.println("Invalid key size - unlimited strength crypto NOT installed!");
            return false;
        } catch( Exception ex ) {
            System.out.println("Caught unexpected exception: " + ex);
            ex.printStackTrace(System.out);
            return false;
        }
        return true;
    }

    public static void main(String[] args)
    {
        if ( isUnlimitedStrengthCryptoAvailable() ) {
            System.out.println("Unlimited strength crypto IS available.");
        } else {
            System.out.println("Unlimited strength crypto is NOT available.");
        }
        System.exit( isUnlimitedStrengthCryptoAvailable() ? 0 : 1 );
    }
}