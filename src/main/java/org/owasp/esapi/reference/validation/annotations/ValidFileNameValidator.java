package org.owasp.esapi.reference.validation.annotations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


public class ValidFileNameValidator implements ConstraintValidator<ValidFileName, String>{
     
    private String context;
    private String[] allowedExtensions;
    private boolean allowNull;

    @Override
    public void initialize(ValidFileName validFileName) {
        context = validFileName.context();
        allowedExtensions = validFileName.allowedExtensions();
        allowNull = validFileName.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        if (input == null) {
            return true;
        }
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid;
        if(allowedExtensions.length == 0){
            valid = ESAPI.validator().isValidFileName(context, input, allowNull, errorList);
        } else {
            List<String> allowedExtensionsList = new ArrayList<>(Arrays.asList(allowedExtensions));
            valid = ESAPI.validator().isValidFileName(context, input, allowedExtensionsList, allowNull, errorList);
        }
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
