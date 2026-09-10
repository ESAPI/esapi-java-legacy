package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidIntegerValidator implements ConstraintValidator<ValidInteger, String>{
     
    private String context;
    private int minValue;
    private int maxValue;
    private boolean allowNull;

    @Override
    public void initialize(ValidInteger validInteger) {
        context = validInteger.context();
        minValue = validInteger.minValue();
        maxValue = validInteger.maxValue();
        allowNull = validInteger.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidInteger(context, input, minValue, maxValue, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
