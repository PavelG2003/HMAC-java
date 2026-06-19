package ru.yandex.practicum;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public final class HmacHttpServer {
    private static final Gson GSON = new Gson();
    private static final Logger LOGGER = Logger.getLogger(HmacHttpServer.class.getName());

    private final AppConfig config;
    private final HmacService hmacService;
    private final HttpServer server;

    public HmacHttpServer(AppConfig config) throws IOException {
        this.config = config;
        this.hmacService = new HmacService(config);
        this.server = HttpServer.create(new InetSocketAddress(config.listenPort()), 0);
        this.server.createContext("/sign", this::handleSign);
        this.server.createContext("/verify", this::handleVerify);
        this.server.setExecutor(Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()));
    }

    public static void configureLogging() {
        try {
            Logger root = Logger.getLogger("");
            FileHandler handler = new FileHandler("hmac-server.log", true);
            handler.setFormatter(new SimpleFormatter());
            root.addHandler(handler);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "File logging is unavailable: {0}", e.getMessage());
        }
    }

    public void start() {
        server.start();
        LOGGER.log(Level.INFO, "HMAC server started on port {0}", config.listenPort());
    }

    public void stop(int delaySeconds) {
        server.stop(delaySeconds);
    }

    private void handleSign(HttpExchange exchange) throws IOException {
        try {
            requirePost(exchange);
            requireJson(exchange);
            JsonObject body = readJson(exchange);
            String msg = requireMsg(body);
            String signature = hmacService.sign(msg);
            LOGGER.log(Level.INFO, "Signed message, msgBytes={0}", msg.getBytes(StandardCharsets.UTF_8).length);
            send(exchange, 200, Collections.singletonMap("signature", signature));
        } catch (ValidationException e) {
            LOGGER.log(Level.WARNING, "Sign request rejected: {0}", e.errorCode());
            send(exchange, e.status(), Collections.singletonMap("error", e.errorCode()));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Internal sign error", e);
            send(exchange, 500, Collections.singletonMap("error", "internal"));
        }
    }

    private void handleVerify(HttpExchange exchange) throws IOException {
        try {
            requirePost(exchange);
            requireJson(exchange);
            JsonObject body = readJson(exchange);
            String msg = requireMsg(body);
            String signature = requireString(body, "signature", "invalid_signature_format");
            boolean ok = hmacService.verify(msg, signature);
            LOGGER.log(Level.INFO, "Verified message, msgBytes={0}, ok={1}",
                    new Object[]{msg.getBytes(StandardCharsets.UTF_8).length, ok});
            send(exchange, 200, Collections.singletonMap("ok", ok));
        } catch (ValidationException e) {
            LOGGER.log(Level.WARNING, "Verify request rejected: {0}", e.errorCode());
            send(exchange, e.status(), Collections.singletonMap("error", e.errorCode()));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Internal verify error", e);
            send(exchange, 500, Collections.singletonMap("error", "internal"));
        }
    }

    private void requirePost(HttpExchange exchange) {
        if (!"POST".equals(exchange.getRequestMethod())) {
            throw new ValidationException(405, "method_not_allowed");
        }
    }

    private void requireJson(HttpExchange exchange) {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().contains("application/json")) {
            throw new ValidationException(415, "unsupported_media_type");
        }
    }

    private JsonObject readJson(HttpExchange exchange) throws IOException {
        byte[] bytes = readLimited(exchange.getRequestBody(), config.maxMsgSizeBytes() + 4096);
        try {
            JsonElement element = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8));
            if (!element.isJsonObject()) {
                throw new ValidationException(400, "invalid_json");
            }
            return element.getAsJsonObject();
        } catch (JsonParseException | IllegalStateException e) {
            throw new ValidationException(400, "invalid_json");
        }
    }

    private byte[] readLimited(InputStream inputStream, int limit) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int total = 0;
        int read;
        while ((read = inputStream.read(chunk)) != -1) {
            total += read;
            if (total > limit) {
                throw new ValidationException(413, "payload_too_large");
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    private String requireMsg(JsonObject body) {
        String msg = requireString(body, "msg", "invalid_msg");
        int msgBytes = msg.getBytes(StandardCharsets.UTF_8).length;
        if (msg.isEmpty()) {
            throw new ValidationException(400, "invalid_msg");
        }
        if (msgBytes > config.maxMsgSizeBytes()) {
            throw new ValidationException(413, "payload_too_large");
        }
        return msg;
    }

    private String requireString(JsonObject body, String name, String errorCode) {
        if (!body.has(name) || !body.get(name).isJsonPrimitive() || !body.get(name).getAsJsonPrimitive().isString()) {
            throw new ValidationException(400, errorCode);
        }
        String value = body.get(name).getAsString();
        if (value.getBytes(StandardCharsets.UTF_8).length > config.maxMsgSizeBytes()) {
            throw new ValidationException(413, "payload_too_large");
        }
        return value;
    }

    private void send(HttpExchange exchange, int status, Map<String, ?> payload) throws IOException {
        byte[] response = GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, response.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(response);
        }
    }
}
