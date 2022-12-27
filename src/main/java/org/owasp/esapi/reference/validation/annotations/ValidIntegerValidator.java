package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


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
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidInteger(context, input, minValue, maxValue, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
