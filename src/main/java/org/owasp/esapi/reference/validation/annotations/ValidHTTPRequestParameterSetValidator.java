package org.owasp.esapi.reference.validation.annotations;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidHTTPRequestParameterSetValidator implements ConstraintValidator<ValidHTTPRequestParameterSet, HttpServletRequest>{
     
    private String context;
    private String[] requiredNames;
    private String[] optionalNames;

    @Override
    public void initialize(ValidHTTPRequestParameterSet validHTTPRequestParameters) {
        context = validHTTPRequestParameters.context();
        requiredNames = validHTTPRequestParameters.requiredNames();
        optionalNames = validHTTPRequestParameters.optionalNames();
    }
 
    @Override
    public boolean isValid(HttpServletRequest input, ConstraintValidatorContext constraintValidatorContext) {
        ValidationErrorList errorList = new ValidationErrorList();
        Set<String> requiredNamesSet = new HashSet<>(Arrays.asList(requiredNames));
        Set<String> optionalNamesSet = new HashSet<>(Arrays.asList(optionalNames));
        boolean valid = DefaultValidator.getInstance().isValidHTTPRequestParameterSet(context, input, requiredNamesSet, optionalNamesSet, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
