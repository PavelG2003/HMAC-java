package ru.yandex.practicum;

import java.nio.file.Path;
import java.nio.file.Paths;

public class ServerHMAC {
    public static void main(String[] args) {
        Path configPath = Paths.get("config.json");
        if (args.length > 0 && "rotate-secret".equals(args[0])) {
            if (args.length > 1) {
                configPath = Paths.get(args[1]);
            }
            AppConfig.rotateSecret(configPath);
            System.out.println("Secret rotated in " + configPath);
            return;
        }
        if (args.length > 1 && "--config".equals(args[0])) {
            configPath = Paths.get(args[1]);
        }
        HmacHttpServer.configureLogging();
        try {
            AppConfig config = AppConfig.load(configPath);
            new HmacHttpServer(config).start();
        } catch (ConfigException e) {
            System.err.println("Config error: " + e.getMessage());
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Internal error: " + e.getMessage());
            System.exit(1);
        }
    }
}
