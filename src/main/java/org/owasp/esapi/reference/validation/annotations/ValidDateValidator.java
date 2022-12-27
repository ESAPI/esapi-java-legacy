package org.owasp.esapi.reference.validation.annotations;

import java.text.DateFormat;
import java.util.Locale;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;


public class ValidDateValidator implements ConstraintValidator<ValidDate, String>{
     
    private String context;
    private int dateStyle;
    private String localeString;
    private boolean allowNull;

    @Override
    public void initialize(ValidDate validDate) {
        context = validDate.context();
        dateStyle = validDate.dateStyle();
        localeString = validDate.locale();
        allowNull = validDate.allowNull();
    }
 
    @Override
    public boolean isValid(String input, ConstraintValidatorContext constraintValidatorContext) {
        Locale locale = new Locale(localeString);
        DateFormat dateFormat = DateFormat.getDateInstance(dateStyle, locale);

        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = DefaultValidator.getInstance().isValidDate(context, input, dateFormat, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolatons(errorList, constraintValidatorContext);
        }
        
        return valid;
    }
}
