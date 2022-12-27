package org.owasp.esapi.reference.validation.annotations;

import java.io.File;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidFileUploadValidator implements ConstraintValidator<ValidFileUpload, byte[]>{
     
    private String context;
    private String directoryPath;
    private String fileName;
    private String parentString;
    private int maxBytes;
    private boolean allowNull;

    @Override
    public void initialize(ValidFileUpload validFileUpload) {
        context = validFileUpload.context();
        directoryPath = validFileUpload.directoryPath();
        fileName = validFileUpload.fileName();
        parentString = validFileUpload.parent();
        maxBytes = validFileUpload.maxBytes();
        allowNull = validFileUpload.allowNull();
    }
 
    @Override
    public boolean isValid(byte[] input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        File parent = new File(parentString);
        boolean valid = DefaultValidator.getInstance().isValidFileUpload(context, directoryPath, fileName, parent, input, maxBytes, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
