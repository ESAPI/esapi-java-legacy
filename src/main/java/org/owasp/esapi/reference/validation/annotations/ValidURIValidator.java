package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


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
        //isValidURI has no method signature that accepts a ValidationErrorList
        //ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidURI(context, input, allowNull);
        
        /*
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        */
        
        return valid;
    }
}
