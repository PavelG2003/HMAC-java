package ru.yandex.practicum;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerHMACTest {
    private static final String SECRET = Base64.getEncoder()
            .encodeToString("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8));
    private static final AppConfig CONFIG = AppConfig.of("SHA256", SECRET, 18080, 16);
    private static final HmacService SERVICE = new HmacService(CONFIG);

    @Test
    void signAndVerifyValidMessage() {
        String signature = SERVICE.sign("hello");

        assertTrue(SERVICE.verify("hello", signature));
    }

    @Test
    void signatureIsDeterministicBase64UrlWithoutPadding() {
        String first = SERVICE.sign("hello");
        String second = SERVICE.sign("hello");

        assertEquals(first, second);
        assertEquals(Codec.HMAC_SHA256_BASE64URL_LENGTH, first.length());
        assertFalse(first.contains("="));
        assertDoesNotThrow(() -> Codec.decodeSignature(first));
    }

    @Test
    void changedSignatureDoesNotVerify() {
        String signature = SERVICE.sign("hello");
        char replacement = signature.charAt(0) == 'A' ? 'B' : 'A';
        String changed = replacement + signature.substring(1);

        assertFalse(SERVICE.verify("hello", changed));
    }

    @Test
    void changedMessageDoesNotVerify() {
        String signature = SERVICE.sign("hello");

        assertFalse(SERVICE.verify("hello!", signature));
    }

    @Test
    void rejectsInvalidBase64UrlSignature() {
        ValidationException exception = assertThrows(ValidationException.class, () -> Codec.decodeSignature("@@@"));

        assertEquals(400, exception.status());
        assertEquals("invalid_signature_format", exception.errorCode());
    }

    @Test
    void rejectsWrongSignatureLength() {
        ValidationException exception = assertThrows(ValidationException.class, () -> Codec.decodeSignature("abcd"));

        assertEquals("invalid_signature_format", exception.errorCode());
    }

    @Test
    void configRejectsInvalidSecret() {
        assertThrows(ConfigException.class, () -> AppConfig.of("SHA256", "not-base64", 8080, 1024));
    }

    @Test
    void configRejectsShortSecret() {
        String shortSecret = Base64.getEncoder().encodeToString("short".getBytes(StandardCharsets.UTF_8));

        assertThrows(ConfigException.class, () -> AppConfig.of("SHA256", shortSecret, 8080, 1024));
    }

    @Test
    void httpSignAndVerifyFlowWorks() throws Exception {
        HmacHttpServer server = startServer(18081, 64);
        try {
            HttpResponse sign = postJson(18081, "/sign", "{\"msg\":\"hello\"}", "application/json");
            String signature = extractSignature(sign.body);
            HttpResponse verify = postJson(18081, "/verify",
                    "{\"msg\":\"hello\",\"signature\":\"" + signature + "\"}", "application/json");

            assertEquals(200, sign.status);
            assertEquals(Codec.HMAC_SHA256_BASE64URL_LENGTH, signature.length());
            assertEquals(200, verify.status);
            assertTrue(verify.body.contains("\"ok\":true"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void httpRejectsInvalidInput() throws Exception {
        HmacHttpServer server = startServer(18082, 4);
        try {
            HttpResponse invalidSignature = postJson(18082, "/verify",
                    "{\"msg\":\"hey\",\"signature\":\"@@@\"}", "application/json");
            HttpResponse emptyMsg = postJson(18082, "/sign", "{\"msg\":\"\"}", "application/json");
            HttpResponse tooLarge = postJson(18082, "/sign", "{\"msg\":\"hello\"}", "application/json");
            HttpResponse wrongContentType = postJson(18082, "/sign", "{\"msg\":\"hey\"}", "text/plain");

            assertEquals(400, invalidSignature.status);
            assertTrue(invalidSignature.body.contains("invalid_signature_format"));
            assertEquals(400, emptyMsg.status);
            assertTrue(emptyMsg.body.contains("invalid_msg"));
            assertEquals(413, tooLarge.status);
            assertEquals(415, wrongContentType.status);
        } finally {
            server.stop(0);
        }
    }

    private static HmacHttpServer startServer(int port, int maxMsgSizeBytes) throws IOException {
        HmacHttpServer server = new HmacHttpServer(AppConfig.of("SHA256", SECRET, port, maxMsgSizeBytes));
        server.start();
        return server;
    }

    private static HttpResponse postJson(int port, String path, String body, String contentType) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://localhost:" + port + path).openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", contentType);
        connection.setDoOutput(true);
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(bytes.length);
        try (OutputStream outputStream = connection.getOutputStream()) {
            outputStream.write(bytes);
        }
        int status = connection.getResponseCode();
        byte[] response = (status >= 400 ? connection.getErrorStream() : connection.getInputStream()).readAllBytes();
        return new HttpResponse(status, new String(response, StandardCharsets.UTF_8));
    }

    private static String extractSignature(String body) {
        String prefix = "{\"signature\":\"";
        assertTrue(body.startsWith(prefix));
        return body.substring(prefix.length(), body.length() - 2);
    }

    private static final class HttpResponse {
        private final int status;
        private final String body;

        private HttpResponse(int status, String body) {
            this.status = status;
            this.body = body;
        }
    }
}
