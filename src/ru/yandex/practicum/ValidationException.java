package ru.yandex.practicum;

public class ValidationException extends RuntimeException {
    private final int status;
    private final String errorCode;

    public ValidationException(int status, String errorCode) {
        super(errorCode);
        this.status = status;
        this.errorCode = errorCode;
    }

    public int status() {
        return status;
    }

    public String errorCode() {
        return errorCode;
    }
}
