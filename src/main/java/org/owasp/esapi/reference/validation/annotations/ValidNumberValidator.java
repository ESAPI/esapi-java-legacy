package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidNumberValidator implements ConstraintValidator<ValidNumber, String>{
     
    private String context;
    private long minValue;
    private long maxValue;
    private boolean allowNull;

    @Override
    public void initialize(ValidNumber validNumber) {
        context = validNumber.context();
        minValue = validNumber.minValue();
        maxValue = validNumber.maxValue();
        allowNull = validNumber.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidNumber(context, input, minValue, maxValue, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
