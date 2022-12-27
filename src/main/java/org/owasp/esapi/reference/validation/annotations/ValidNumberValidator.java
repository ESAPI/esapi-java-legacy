package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


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
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidNumber(context, input, minValue, maxValue, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
