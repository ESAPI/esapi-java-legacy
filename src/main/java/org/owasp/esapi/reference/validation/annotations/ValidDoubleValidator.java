package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidDoubleValidator implements ConstraintValidator<ValidDouble, String>{
     
    private String context;
    private double minValue;
    private double maxValue;
    private boolean allowNull;

    @Override
    public void initialize(ValidDouble validDouble) {
        context = validDouble.context();
        minValue = validDouble.minValue();
        maxValue = validDouble.maxValue();
        allowNull = validDouble.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidDouble(context, input, minValue, maxValue, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
