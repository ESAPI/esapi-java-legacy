package org.owasp.esapi.reference.validation.annotations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


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
        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid;
        if(allowedExtensions.length == 0){
            valid = DefaultValidator.getInstance().isValidFileName(context, input, allowNull, errorList);
        } else {
            List<String> allowedExtensionsList = new ArrayList<>(Arrays.asList(allowedExtensions));
            valid = DefaultValidator.getInstance().isValidFileName(context, input, allowedExtensionsList, allowNull, errorList);
        }
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
