package com.t1.authservice.exception;

import org.springframework.security.core.AuthenticationException;

public class MissingAuthorizationHeaderException extends AuthenticationException {
    public MissingAuthorizationHeaderException(String message) {
        super(message);
    }
}

