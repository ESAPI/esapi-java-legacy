package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidCreditCardValidator implements ConstraintValidator<ValidCreditCard, String>{
     
    private String context;
    private boolean allowNull;

    @Override
    public void initialize(ValidCreditCard validCreditCard) {
        context = validCreditCard.context();
        allowNull = validCreditCard.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidCreditCard(context, input, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
