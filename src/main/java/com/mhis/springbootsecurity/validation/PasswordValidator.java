package com.mhis.springbootsecurity.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class PasswordValidator {
    public static List<String> validate(String password){
        List<String> errors = new ArrayList<>();

        if(password.length() < 8){
            errors.add("Password must be greater than 8 characters");
        }

        if(!Pattern.compile("[A-Z]").matcher(password).find()){
            errors.add("Password must contain at least one upper case " +
                    "letter!");
        }

        if(!Pattern.compile("[a-z]").matcher(password).find()){
            errors.add("Password must contain at least one lowercase " +
                    "letter!");
        }

        if(!Pattern.compile("\\d").matcher(password).find()){
            errors.add("Password must contain at least one number!");
        }

        if(!Pattern.compile("[@#$%^&+=!]").matcher(password).find()){
            errors.add("Password must contain at least one number!");
        }

        return errors;
    }
}
