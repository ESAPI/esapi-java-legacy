package org.owasp.esapi.reference.validation.annotations;

import java.io.File;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidDirectoryPathValidator implements ConstraintValidator<ValidDirectoryPath, String>{
     
    private String context;
    private String parentString;
    private boolean allowNull;

    @Override
    public void initialize(ValidDirectoryPath validDirectoryPath) {
        context = validDirectoryPath.context();
        parentString = validDirectoryPath.parent();
        allowNull = validDirectoryPath.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        File parent = new File(parentString);
        boolean valid = DefaultValidator.getInstance().isValidDirectoryPath(context, input, parent, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
