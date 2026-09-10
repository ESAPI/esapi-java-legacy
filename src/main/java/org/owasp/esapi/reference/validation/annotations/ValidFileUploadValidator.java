package org.owasp.esapi.reference.validation.annotations;

import java.io.File;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


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
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        File parent = new File(parentString);
        boolean valid = ESAPI.validator().isValidFileUpload(context, directoryPath, fileName, parent, input, maxBytes, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
