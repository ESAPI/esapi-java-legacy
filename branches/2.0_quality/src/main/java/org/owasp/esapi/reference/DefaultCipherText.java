package org.owasp.esapi.reference;

import org.owasp.esapi.CipherText;
// Still working on this.
/**
 * Reference implementation of <code>CipherText</code>.
 * <p>
 * Copyright (c) 2009 - The OWASP Foundation
 * </p>
 * @author kevin.w.wall@gmail.com
 * @since 2.0
 */
public class DefaultCipherText implements CipherText {

	/**
	 *  {@inheritDoc}
	 */
	public String getCipherTransformation() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 *  {@inheritDoc}
	 */
	public String getCipherAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 *  {@inheritDoc}
	 */
	public String getCipherMode() {
		// TODO Auto-generated method stub
		return null;
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public String getPaddingScheme() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 *  {@inheritDoc}
	 */
	public byte[] getIV() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 *  {@inheritDoc}
	 */
	public byte[] getRawCipherText() {
		// TODO Auto-generated method stub
		return null;
	}
	
	/**
	 *  {@inheritDoc}
	 */
	public String getEncodedCipherText() {
		// TODO Auto-generated method stub
		return null;
	}
	
	/**
	 * {@inheritDoc}
	 */ 
	public boolean validateMIC() {
		// TODO Auto-generated method stub
		return false;
	}

	public byte[] getNonce() {
		// TODO Auto-generated method stub
		return null;
	}
}
