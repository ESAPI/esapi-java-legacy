package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidPrintableValidator implements ConstraintValidator<ValidPrintable, char[]>{
     
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
    public boolean isValid(char[] input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidPrintable(context, input, maxLength, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
