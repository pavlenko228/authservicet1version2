package com.t1.authservice.exception;

public class SuchUserExistsException extends RuntimeException {
    public SuchUserExistsException(String message) {
        super(message);
    }

}
