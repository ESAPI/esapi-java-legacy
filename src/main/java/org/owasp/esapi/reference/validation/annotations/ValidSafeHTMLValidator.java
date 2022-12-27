package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


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
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidSafeHTML(context, input, maxLength, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
