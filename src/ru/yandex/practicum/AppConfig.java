package ru.yandex.practicum;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

public final class AppConfig {
    private static final Gson GSON = new Gson();
    private static final int MIN_SECRET_BYTES = 32;

    private String hmacAlg;
    private String secret;
    private int listenPort;
    private int maxMsgSizeBytes;

    public static AppConfig load(Path path) {
        try {
            AppConfig config = GSON.fromJson(Files.readString(path, StandardCharsets.UTF_8), AppConfig.class);
            if (config == null) {
                throw new ConfigException("Config is empty");
            }
            config.validate();
            return config;
        } catch (IOException | JsonParseException e) {
            throw new ConfigException("Cannot read config: " + e.getMessage(), e);
        }
    }

    public static AppConfig of(String hmacAlg, String secret, int listenPort, int maxMsgSizeBytes) {
        AppConfig config = new AppConfig();
        config.hmacAlg = hmacAlg;
        config.secret = secret;
        config.listenPort = listenPort;
        config.maxMsgSizeBytes = maxMsgSizeBytes;
        config.validate();
        return config;
    }

    public static String generateSecret() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static void rotateSecret(Path path) {
        AppConfig config = load(path);
        config.secret = generateSecret();
        try {
            Files.writeString(path, GSON.toJson(config) + System.lineSeparator(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ConfigException("Cannot update config: " + e.getMessage(), e);
        }
    }

    public String macAlgorithm() {
        return hmacAlg;
    }

    public byte[] secretBytes() {
        try {
            byte[] bytes = Base64.getDecoder().decode(secret);
            if (bytes.length < MIN_SECRET_BYTES) {
                throw new ConfigException("Secret must contain at least " + MIN_SECRET_BYTES + " bytes");
            }
            return bytes;
        } catch (IllegalArgumentException e) {
            throw new ConfigException("Secret must be valid base64", e);
        }
    }

    public int listenPort() {
        return listenPort;
    }

    public int maxMsgSizeBytes() {
        return maxMsgSizeBytes;
    }

    private void validate() {
        if (!Objects.equals(hmacAlg, "SHA256") && !Objects.equals(hmacAlg, "HmacSHA256")) {
            throw new ConfigException("Only SHA256 HMAC is supported");
        }
        if (listenPort < 1 || listenPort > 65535) {
            throw new ConfigException("listenPort must be in range 1..65535");
        }
        if (maxMsgSizeBytes < 1) {
            throw new ConfigException("maxMsgSizeBytes must be positive");
        }
        secretBytes();
    }
}
