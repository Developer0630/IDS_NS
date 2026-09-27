package com.ltm.ids.exception;

import com.ltm.ids.dto.ApiResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ApiResponse<String> handleUnexpectedException(Exception exception) {
        return new ApiResponse<>(false, exception.getMessage());
    }
}
