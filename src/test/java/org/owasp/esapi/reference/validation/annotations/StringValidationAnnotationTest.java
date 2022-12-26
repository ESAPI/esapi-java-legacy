package org.owasp.esapi.reference.validation.annotations;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Valid;
import javax.validation.Validation;
import javax.validation.Validator;

import org.junit.Before;
import org.junit.Test;

import junit.framework.TestCase;


public class StringValidationAnnotationTest extends TestCase {

    private String validString = "John";

    private String invalidStringType = "John<script>";

    private String invalidStringLength = "John John John John John John John";

    private Validator validator;

    @Before
    public void setUp() {
        validator = Validation.buildDefaultValidatorFactory().getValidator();
    }

    @Test
    public void testValidString(){
        Person p = new Person(validString);
        Set<ConstraintViolation<Person>> violations = validator.validate(p);
        assertEquals(0, violations.size());
    }

    @Test
    public void testInvalidStringType(){
        Person p = new Person(invalidStringType);
        Set<ConstraintViolation<Person>> violations = validator.validate(p);
        assertEquals(2, violations.size());
    }

    @Test
    public void testInvalidStringLength(){
        Person p = new Person(invalidStringLength);
        Set<ConstraintViolation<Person>> violations = validator.validate(p);
        assertEquals(2, violations.size());
    }

    @Test
    public void testInvalidStringCascading(){
        Person p = new Person(invalidStringLength);
        List<Person> people = new ArrayList<>();
        people.add(p);
        Department d = new Department(people);
        Set<ConstraintViolation<Department>> violations = validator.validate(d);
        assertEquals(2, violations.size());
    }
}

class Person {

    @ValidString(context = "name", type = "SafeString", maxLength = 32)
    private String name;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Person(String name){
        this.setName(name);
    }
}

class Department {

    @Valid
    private List<Person> people;

    public Department(List<Person> people) {
        this.people = people;
    }
}