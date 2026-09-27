package com.ltm.ids.dto;

public record ApiResponse<T>(boolean success, T data) {

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data);
    }
}
