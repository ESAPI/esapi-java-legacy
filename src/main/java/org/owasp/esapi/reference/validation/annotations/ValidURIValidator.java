package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidURIValidator implements ConstraintValidator<ValidURI, String>{
     
    private String context;
    private boolean allowNull;

    @Override
    public void initialize(ValidURI validURI) {
        context = validURI.context();
        allowNull = validURI.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        //isValidURI has no method signature that accepts a ValidationErrorList
        //ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidURI(context, input, allowNull);
        
        /*
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        */
        
        return valid;
    }
}
