package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;


public class ValidPrintableStringValidator implements ConstraintValidator<ValidPrintable, String>{
     
    private String context;
    private int maxLength;
    private boolean allowNull;

    @Override
    public void initialize(ValidPrintable validPrintable) {
        context = validPrintable.context();
        maxLength = validPrintable.maxLength();
        allowNull = validPrintable.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidPrintable(context, input, maxLength, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
