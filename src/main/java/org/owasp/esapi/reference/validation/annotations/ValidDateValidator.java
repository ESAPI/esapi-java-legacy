package org.owasp.esapi.reference.validation.annotations;

import java.text.DateFormat;
import java.util.Locale;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.ESAPI;


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
        if (input == null) {
            return true;
        }
        Locale locale = toLocale(localeString);
        DateFormat dateFormat = DateFormat.getDateInstance(dateStyle, locale);

        ValidationErrorList errorList = new ValidationErrorList();
        boolean valid = ESAPI.validator().isValidDate(context, input, dateFormat, allowNull, errorList);
        
        if(!valid){
            ValidationUtil.addViolations(errorList, constraintValidatorContext);
        }
        
        return valid;
    }

    private static Locale toLocale(String localeValue) {
        if (localeValue == null) {
            return Locale.getDefault();
        }
        String normalized = localeValue.trim();
        if (normalized.isEmpty()) {
            return Locale.getDefault();
        }
        Locale locale = Locale.forLanguageTag(normalized.replace('_', '-'));
        return Locale.ROOT.equals(locale) ? Locale.getDefault() : locale;
    }
}
