package org.owasp.esapi.reference.validation.annotations;

import java.util.Arrays;
import java.util.List;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidListItemValidator implements ConstraintValidator<ValidListItem, String>{
     
    private String context;
    private String[] listArray;

    @Override
    public void initialize(ValidListItem validListItem) {
        context = validListItem.context();
        listArray = validListItem.list();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        List<String> list = Arrays.asList(listArray);
        boolean valid = DefaultValidator.getInstance().isValidListItem(context, input, list, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
