package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidSafeHTMLValidator implements ConstraintValidator<ValidSafeHTML, String>{
     
    private String context;
    private int maxLength;
    private boolean allowNull;

    @Override
    public void initialize(ValidSafeHTML validSafeHTML) {
        context = validSafeHTML.context();
        maxLength = validSafeHTML.maxLength();
        allowNull = validSafeHTML.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidSafeHTML(context, input, maxLength, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
