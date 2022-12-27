package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidFileContentValidator implements ConstraintValidator<ValidFileContent, byte[]>{
     
    private String context;
    private int maxBytes;
    private boolean allowNull;

    @Override
    public void initialize(ValidFileContent validFileContent) {
        context = validFileContent.context();
        maxBytes = validFileContent.maxBytes();
        allowNull = validFileContent.allowNull();
    }
 
    @Override
    public boolean isValid(byte[] input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidFileContent(context, input, maxBytes, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
