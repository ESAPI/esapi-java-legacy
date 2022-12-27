package org.owasp.esapi.reference.validation.annotations;

import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.errors.ValidationException;

public class ValidationUtil {

    private ValidationUtil(){}

    public static void addViolatons(ValidationErrorList errorList, ConstraintValidatorContext constraintValidatorContext){
        for (ValidationException vex : errorList.errors()) {
            String errorMessage = vex.getLogMessage();
            constraintValidatorContext.buildConstraintViolationWithTemplate(errorMessage).addConstraintViolation();
        }
    }
    
}
