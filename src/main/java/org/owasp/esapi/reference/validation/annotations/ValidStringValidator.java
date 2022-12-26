package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidStringValidator implements ConstraintValidator<ValidString, String>{
     
    private String context;
    private String type;
    private int maxLength;
    private boolean allowNull;
    private boolean canonicalize; 

    @Override
    public void initialize(ValidString validString) {
        context = validString.context();
        type = validString.type();
        maxLength = validString.maxLength();
        allowNull = validString.allowNull();
        canonicalize = validString.canonicalize();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidInput(context, input, type, maxLength, allowNull, canonicalize, errorList);
        
        if(!valid){
            for (ValidationException vex : errorList.errors()) {
                String errorMessage = vex.getLogMessage();
                constraintContext.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();
            }
        }
        
        return valid;
    }
}