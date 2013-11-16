package org.owasp.esapi.crypto;

// NOTE: This class is not complete.
// DISCUSS: Should some of these methods be package level...e.g., parts
//			of the KDF context that JavaEncryptor sets such as the
//			cipher transformation, etc.???

/**
 * This class is used with {@code KeyDerivationFunction} to set the
 * "context" for the KDF. This allows one to use the same main key
 * between different parties to result with different derived keys
 * for each party.
 */
public class KDFContext {

	private String cipherXform_ = "";
	private int    kdfVersion_  = KeyDerivationFunction.kdfVersion;
	private String prfAlgName_  = "";
	private int    keySize_     = 128;  // ???
	private String usage_       = "";
	private String sender_      = "";
	private String recipient_   = "";

	public KDFContext() {
		// TODO
	}
	
	public String getCipherXform() {
		return cipherXform_;
	}
	
	public KDFContext setCipherXform(String cipherXform) {
		cipherXform_ = notNullOrEmpty("cipherXform", cipherXform);
        return this;
	}
	
	public int getKdfVersion() {
		return kdfVersion_;
    }

	public KDFContext setKdfVersion(int kdfVersion) {
		kdfVersion_ = kdfVersion;	// Need sanity check here.
        return this;
	}
	
	public String getPrfAlgName() {
		return prfAlgName_;
	}
	
	public KDFContext setPrfAlgName(String prfAlgName) {
		prfAlgName_ = notNullOrEmpty("prfAlgName", prfAlgName);
        return this;
	}
	
	public int getKeySize() {
		return keySize_;
	}
	
	public KDFContext setKeySize(int keySize) {
        assert keySize >= 56 : "Keysize must be at least 56 bits.";
		keySize_ = keySize;
        return this;
	}
	
	public String getUsage() {
		return usage_;
	}
	
	public KDFContext setUsage(String usage) {
		usage_ = notNullOrEmpty("usage", usage);
        return this;
	}
	
	public String getSender() {
		return sender_;
	}
	
	public KDFContext setSender(String sender) {
		sender_ = notNullOrEmpty("sender", sender);
		return this;
	}
	
	public String getRecipient() {
		return recipient_;
	}

	public KDFContext setRecipient(String recipient) {
		recipient_ = notNullOrEmpty("recipient", recipient);
		return this;
	}

    public String toString() {
    	//
        // Do NOT change this order or the delimiter--EVER--or old stored
    	// ciphertext will no longer be able to be decrypted because the
    	// derived keys would be computed differently.
    	//
        StringBuffer context = new StringBuffer(64);
        context.append(cipherXform_);
        context.append(":").append(kdfVersion_);
        context.append(":").append(prfAlgName_);
        context.append(":").append(keySize_);
        context.append(":").append(usage_);
        context.append(":").append(sender_);
        context.append(":").append(recipient_);
        
        return context.toString();
    }
    
    @Override
    public int hashCode() {
    	return this.toString().hashCode();
    }
    
    @Override
    public boolean equals(Object obj) {
    	return this.toString().equals(obj);
    }
    
    private static String notNullOrEmpty(String varName, String value)
        throws IllegalArgumentException
    {
        varName = (varName != null) ? varName : "Variable";
        if ( value == null || "".equals(value) ) {
            throw new IllegalArgumentException(varName +
                                               " cannot be null or empty.");
        }
        return value;
    }
}