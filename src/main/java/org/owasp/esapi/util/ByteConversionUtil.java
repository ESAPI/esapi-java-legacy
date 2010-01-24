/*
 * OWASP Enterprise Security API (ESAPI)
 * 
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright &copy; 2010 - The OWASP Foundation
 */
package org.owasp.esapi.util;

/**
 * Conversion to/from byte arrays to/from short, int, long. The assumption
 * is that they byte arrays are in network byte order (i.e., big-endian
 * ordered).
 *
 * @see org.owasp.esapi.crypto.CipherTextSerializer
 * @author kevin.w.wall@gmail.com
 */
public class ByteConversionUtil {

    ////////// Convert from short, int, long to byte array. //////////

    /**
     * Returns a byte array containing 2 network byte ordered bytes representing
     * the given {@code short}.
     *
     * @param input An {@code short} to convert to a byte array.
     * @return A byte array representation of an {@code short} in network byte
     * order (i.e., big-endian order).
     */
    public static byte[] fromShort(short input) {
        byte[] output = new byte[2];
        output[0] = (byte) (input >> 8);
        output[1] = (byte) input;
        return output;
    }

    /**
     * Returns a byte array containing 4 network byte-ordered bytes representing the
     * given {@code int}.
     *
     * @param input An {@code int} to convert to a byte array.
     * @return A byte array representation of an {@code int} in network byte order
     * (i.e., big-endian order).
     */
    public static byte[] fromInt(int input) {
        byte[] output = new byte[4];
        output[0] = (byte) (input >> 24);
        output[1] = (byte) (input >> 16);
        output[2] = (byte) (input >> 8);
        output[3] = (byte) input;
        return output;
    }

    /**
     * Returns a byte array containing 8 network byte-ordered bytes representing
     * the given {@code long}.
     *
     * @param input The {@code long} to convert to a {@code byte} array.
     * @return A byte array representation of a {@code long}.
     */
    public static byte[] fromLong(long input) {
        byte[] output = new byte[8];
            // Note: I've tried using '>>>' instead of '>>' but that seems to
            //       make no difference. The testLongConversion() still fails
            //       in the same manner.
        output[0] = (byte) (input >> 56);
        output[1] = (byte) (input >> 48);
        output[2] = (byte) (input >> 40);
        output[3] = (byte) (input >> 32);
        output[4] = (byte) (input >> 24);
        output[5] = (byte) (input >> 16);
        output[6] = (byte) (input >> 8);
        output[7] = (byte) input;
        return output;
    }

    ////////// Convert from byte array to short, int, long. //////////

    /**
     * Converts a given byte array to an {@code short}. Bytes are expected in
     * network byte
     * order.
     *
     * @param input A network byte-ordered representation of an {@code short}.
     * @return The {@code short} value represented by the input array.
     */
    public static short toShort(byte[] input) {
        assert input.length == 2 : "toShort(): Byte array length must be 2.";
        short output = 0;
        output = (short)(((input[0] & 0xff) << 8) | (input[1] & 0xff));
        return output;
    }

    /**
     * Converts a given byte array to an {@code int}. Bytes are expected in
     * network byte order.
     *
     * @param input A network byte-ordered representation of an {@code int}.
     * @return The {@code int} value represented by the input array.
     */
    public static int toInt(byte[] input) {
        assert input.length == 4 : "toInt(): Byte array length must be 4.";
        int output = 0;
        output = ((input[0] & 0xff) << 24) | ((input[1] & 0xff) << 16) |
                 ((input[2] & 0xff) << 8) | (input[3] & 0xff);
        return output;
    }

    /**
     * Converts a given byte array to a {@code long}. Bytes are expected in
     * network byte
     *
     * @param input A network byte-ordered representation of a {@code long}.
     * @return The {@code long} value represented by the input array
     */
    @SuppressWarnings("cast")
    public static long toLong(byte[] input) {  // FIXME: Failing in testLongConversion()
        assert input.length == 8 : "toLong(): Byte array length must be 8.";
        long output = 0;
    // Tried both of these ways, each w/ and w/out casts, but
    // testLongConversion() still failing.
//        output = (long)((input[0] & 0xff) << 56) | ((input[1] & 0xff) << 48) |
//                 ((input[2] & 0xff) << 40) | ((input[3] & 0xff) << 32) |
//                 ((input[4] & 0xff) << 24) | ((input[5] & 0xff) << 16) |
//                 ((input[6] & 0xff) << 8)  | (input[7] & 0xff);
        output  = (long)((input[0] & 0xff) << 56);
        output |= (long)((input[1] & 0xff) << 48);
        output |= (long)((input[2] & 0xff) << 40);
        output |= (long)((input[3] & 0xff) << 32);
        output |= (long)((input[4] & 0xff) << 24);
        output |= (long)((input[5] & 0xff) << 16);
        output |= (long)((input[6] & 0xff) << 8);
        output |= (long)(input[7] & 0xff);
        return output;
    }
}