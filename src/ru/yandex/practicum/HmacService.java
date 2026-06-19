package ru.yandex.practicum;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public final class HmacService {
    private final byte[] key;
    private final String algorithm;

    public HmacService(AppConfig config) {
        this.key = config.secretBytes();
        this.algorithm = config.macAlgorithm();
    }

    public String sign(String msg) {
        return Codec.encodeSignature(signBytes(msg));
    }

    public boolean verify(String msg, String signature) {
        byte[] actual = Codec.decodeSignature(signature);
        byte[] expected = signBytes(msg);
        return MessageDigest.isEqual(expected, actual);
    }

    private byte[] signBytes(String msg) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            return mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot calculate HMAC", e);
        }
    }
}
