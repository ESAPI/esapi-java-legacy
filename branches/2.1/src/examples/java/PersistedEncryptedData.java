import java.io.*;
import org.owasp.esapi.*;
import org.owasp.esapi.crypto.*;
import org.owasp.esapi.errors.*;
import org.owasp.esapi.codecs.*;

/** A slightly more complex example showing encoding encrypted data and writing
 *  it out to a file. This is very similar to the example in the ESAPI User
 *  Guide for "Symmetric Encryption in ESAPI 2.0".
 */
public class PersistedEncryptedData
{
    public enum OutputEncoding { raw, base64, hex }

    private static final OutputEncoding dfltEncoding = OutputEncoding.raw;

    private static boolean useBase64(OutputEncoding encoding) {
        if ( encoding.equals(OutputEncoding.base64) ) {
            return true;
        } else {
            return false;
        }
    }

    private static boolean useHex(OutputEncoding encoding) {
        if ( encoding.equals(OutputEncoding.hex) ) {
            return true;
        } else {
            return false;
        }
    }

    /** Take the specified plaintext, encrypt it, and then persist it
     *  to the specified file name according to the specified encoding.
     *
     * @param plaintext The {@code PlainText} we wish to encrypt.
     * @param filemane  Name of the file in which to store the encrypted, encoded data.
     * @param encoding  How it was encoded. Either base64, hex, or raw (meaning
     *                  no encoding was used).
     * @returns
     * @throws EncryptionException
     * @throws IOException
     * @throws UnsupportedEncodingException
     */
    public static int persistEncryptedData(PlainText plaintext,
                                            String filename,
                                            OutputEncoding encoding)
        throws EncryptionException, IOException, UnsupportedEncodingException
    {
        File serializedFile = new File(filename);
        serializedFile.delete(); // Delete any old serialized file.

        CipherText ct = ESAPI.encryptor().encrypt(plaintext);
        byte[] serializedCiphertext = ct.asPortableSerializedByteArray();
        String encodedStr = null;
        byte[] serializedBytes = null;

        if ( useBase64(encoding) ) {
            encodedStr = Base64.encodeBytes(serializedCiphertext);
            serializedBytes = encodedStr.getBytes("UTF-8");
        } else if ( useHex(encoding) ) {
            encodedStr = Hex.encode(serializedCiphertext, true);
            serializedBytes = encodedStr.getBytes("UTF-8");
        } else {
            serializedBytes = serializedCiphertext;
        }

        FileOutputStream fos = new FileOutputStream(serializedFile);
        fos.write( serializedBytes );
        fos.close();
        return serializedBytes.length;
    }
 
    /** Read the specified file name containing encoded encrypted data,
     *  and then decode it and decrypt it to retrieve the original plaintext.
     *
     * @param encryptedDataFilename Name of the file to read containing the
     *                  encoded, encrypted data.
     * @param encoding  How it was encoded. Either base64, hex, or raw (meaning
     *                  no encoding was used).
     * @returns     The original {@code PlainText} object.
     * @throws EncryptionException
     * @throws IOException
     * @throws UnsupportedEncodingException
     */
    public static PlainText restorePlaintext(String encryptedDataFilename,
                                             OutputEncoding encoding)
        throws EncryptionException, IOException, UnsupportedEncodingException
    {
        File serializedFile = new File(encryptedDataFilename);
        FileInputStream fis = new FileInputStream(serializedFile);
        int avail = fis.available();
        byte[] bytes = new byte[avail];
        fis.read(bytes, 0, avail);
        String encodedEncryptedData = new String(bytes, "UTF-8");

        byte[] serializedCiphertext;

        if ( useBase64(encoding) ) {
            serializedCiphertext = Base64.decode(encodedEncryptedData);
        } else if ( useHex(encoding) ) {
            serializedCiphertext = Hex.decode(encodedEncryptedData);
        } else {
            // Raw encoding
            serializedCiphertext = bytes;
        }
        System.out.println("Serialized ciphertext is " + serializedCiphertext.length +
                           " bytes.");

        CipherText restoredCipherText =
                            CipherText.fromPortableSerializedBytes(serializedCiphertext);
        fis.close();
        PlainText plaintext = ESAPI.encryptor().decrypt(restoredCipherText);
        return plaintext;
    }

    /**
     * Usage: PersistedEncryptedData plaintext filename [{raw|base64|hex}]
     */
    public static void main(String[] args) {

        try {
            String plaintext = null;
            String filename  = null;
            OutputEncoding encoding = dfltEncoding;

            if ( args.length >= 3 ) {
                plaintext = args[0];
                filename  = args[1];
                if ( args[2].equalsIgnoreCase("raw") ) {
                    encoding = OutputEncoding.raw;
                } else if ( args[2].equalsIgnoreCase("base64") ) {
                    encoding = OutputEncoding.base64;
                } else if ( args[2].equalsIgnoreCase("hex") ) {
                    encoding = OutputEncoding.hex;
                } else {
                    System.err.println(args[2] + ": Unrecognized encoding; using default.");
                    encoding = dfltEncoding;
                }
            } else {
                System.err.println("Usage: PersistedEncryptedData plaintext " +
                                   "filename [{raw|base64|hex}]");
                System.exit(2);
            }

            // Add file suffix, appropriate to encoding
            filename = filename + "." + encoding;

            System.out.println("Encrypting " + plaintext.length() +
                               " bytes of plaintext and storing in file '" +
                               filename + "'.");

            int n = PersistedEncryptedData.persistEncryptedData(
                                                    new PlainText(plaintext),
                                                    filename, encoding);

            System.out.println("Wrote " + n + " bytes to encrypted file " + filename + ".");
            File f = new File(filename);
            PlainText pt = PersistedEncryptedData.restorePlaintext(filename, encoding);

            System.out.println("Plaintext recovered from encrypted file was: " + pt);
            if ( pt.toString().equals( plaintext ) ) {
                System.out.println("Plaintext recovered successfully.");
            } else {
                System.out.println("Recovered plaintext differs from original plaintext.");
            }
        } catch(Throwable t) {
            System.err.println("Caught: " + t.getClass().getName() +
                               "; exception msg: " + t);
            t.printStackTrace(System.err);
        }
    }
}
