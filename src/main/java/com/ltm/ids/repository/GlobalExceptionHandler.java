package com.ltm.ids.repository;

import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.ltm.ids.dto.ApiResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ApiResponse<String> handleUnexpectedException(Exception exception) {
        return new ApiResponse<>(false, exception.getMessage());
    }
}
