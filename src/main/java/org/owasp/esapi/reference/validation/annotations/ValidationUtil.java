package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;

public class ValidationUtil {

    private ValidationUtil(){}

    public static void addViolatons(ValidationErrorList errorList, ConstraintValidatorContext constraintValidatorContext){
        constraintValidatorContext.disableDefaultConstraintViolation();
        for (ValidationException vex : errorList.errors()) {
            String errorMessage = vex.getUserMessage();
            if (errorMessage == null || errorMessage.isEmpty()) {
                errorMessage = constraintValidatorContext.getDefaultConstraintMessageTemplate();
            }
            constraintValidatorContext.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();
        }
    }
    
}
