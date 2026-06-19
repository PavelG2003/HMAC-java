package ru.yandex.practicum;

import java.util.Base64;
import java.util.regex.Pattern;

public final class Codec {
    public static final int HMAC_SHA256_BYTES = 32;
    public static final int HMAC_SHA256_BASE64URL_LENGTH = 43;

    private static final Pattern BASE64URL_WITHOUT_PADDING = Pattern.compile("^[A-Za-z0-9_-]+$");

    private Codec() {
    }

    public static String encodeSignature(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static byte[] decodeSignature(String signature) {
        if (signature == null
                || signature.length() != HMAC_SHA256_BASE64URL_LENGTH
                || signature.indexOf('=') >= 0
                || !BASE64URL_WITHOUT_PADDING.matcher(signature).matches()) {
            throw new ValidationException(400, "invalid_signature_format");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(signature);
            if (decoded.length != HMAC_SHA256_BYTES) {
                throw new ValidationException(400, "invalid_signature_format");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new ValidationException(400, "invalid_signature_format");
        }
    }
}
