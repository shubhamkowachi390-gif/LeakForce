import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * LeakForce v1.0 - Java parallel login worker.
 *
 * The Python controller owns the decision logic (success / lockout / rate).
 * This worker only performs HTTP login attempts in parallel and reports raw
 * responses as JSON lines on stdout. It never decides whether a login worked.
 *
 * Usage: java -jar LeakForceWorker.jar <worker-config.tsv>
 */
public final class LeakForceWorker {

    private static final PrintWriter OUT =
            new PrintWriter(new OutputStreamWriter(System.out, StandardCharsets.UTF_8), true);

    private static final AtomicBoolean STOP = new AtomicBoolean(false);
    private static final AtomicInteger COMPLETED = new AtomicInteger(0);
    private static final Object RATE_LOCK = new Object();
    private static long nextSlot = 0L;

    private LeakForceWorker() {
    }

    public static void main(String[] args) {
        long started = System.currentTimeMillis();
        try {
            if (args.length < 1) {
                OUT.println("{\"type\":\"log\",\"level\":\"error\",\"message\":\"Missing worker config path\"}");
                finish(0);
                return;
            }

            Map<String, String> cfg = readTsvMap(args[0]);
            List<String[]> fields = readTsvRows(cfg.getOrDefault("fieldsFile", ""));
            List<String[]> tasks = readTsvRows(cfg.getOrDefault("tasksFile", ""));

            String action = cfg.getOrDefault("action", "").trim();
            String method = cfg.getOrDefault("method", "post").trim().toUpperCase(Locale.ROOT);
            int delayMs = intValue(cfg.get("delayMs"), 1000);
            int concurrency = Math.max(1, Math.min(5, intValue(cfg.get("concurrency"), 1)));
            int timeoutMs = intValue(cfg.get("timeoutMs"), 15000);

            if (action.isEmpty() || tasks.isEmpty()) {
                OUT.println("{\"type\":\"log\",\"level\":\"error\",\"message\":\"Worker started without action URL or tasks\"}");
                finish(0);
                return;
            }

            // The Python controller can send STOP on stdin after a success or lockout.
            Thread stopper = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if ("STOP".equalsIgnoreCase(line.trim())) {
                            STOP.set(true);
                            break;
                        }
                    }
                } catch (Exception ignored) {
                    // stdin closed - normal shutdown
                }
            }, "leakforce-stop-listener");
            stopper.setDaemon(true);
            stopper.start();

            CookieManager cookies = new CookieManager();
            String cookieHeader = cfg.getOrDefault("cookie", "");
            if (!cookieHeader.isBlank()) {
                seedCookies(cookies, URI.create(action), cookieHeader);
            }

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(timeoutMs))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .cookieHandler(cookies)
                    .build();

            URI actionUri;
            try {
                actionUri = URI.create(action);
            } catch (Exception exc) {
                OUT.println("{\"type\":\"log\",\"level\":\"error\",\"message\":\"Invalid action URL: "
                        + escape(exc.getMessage()) + "\"}");
                finish(0);
                return;
            }

            OUT.println("{\"type\":\"log\",\"level\":\"info\",\"message\":\"Java worker started: "
                    + tasks.size() + " attempts, " + concurrency + " thread(s), "
                    + delayMs + " ms delay\"}");

            AtomicInteger nextIndex = new AtomicInteger(0);
            ExecutorService pool = Executors.newFixedThreadPool(concurrency);
            int total = tasks.size();

            for (int workerId = 0; workerId < concurrency; workerId++) {
                pool.submit(() -> {
                    while (!STOP.get()) {
                        int index = nextIndex.getAndIncrement();
                        if (index >= total) {
                            return;
                        }
                        String[] task = tasks.get(index);
                        String username = task.length > 0 ? task[0] : "";
                        String password = task.length > 1 ? task[1] : "";
                        if (!waitForRateSlot(delayMs)) {
                            return;
                        }
                        attempt(client, actionUri, method, fields, username, password,
                                timeoutMs, cfg, index + 1);
                    }
                });
            }

            pool.shutdown();
            while (!pool.awaitTermination(1, TimeUnit.SECONDS)) {
                if (STOP.get()) {
                    pool.shutdownNow();
                    break;
                }
            }

            finish(COMPLETED.get());
        } catch (Exception exc) {
            OUT.println("{\"type\":\"log\",\"level\":\"error\",\"message\":\"Worker fatal: "
                    + escape(String.valueOf(exc)) + "\"}");
            finish(COMPLETED.get());
        } finally {
            OUT.flush();
        }
    }

    private static void finish(int attempted) {
        long elapsed = 0;
        OUT.println("{\"type\":\"worker_done\",\"attempted\":" + attempted + ",\"elapsedMs\":" + elapsed + "}");
        OUT.flush();
    }

    private static void attempt(
            HttpClient client,
            URI actionUri,
            String method,
            List<String[]> fields,
            String username,
            String password,
            int timeoutMs,
            Map<String, String> cfg,
            int number) {

        if (STOP.get()) {
            return;
        }

        long started = System.currentTimeMillis();
        String statusText = "";
        String location = "";
        String body = "";
        int status = 0;
        String error = "";

        try {
            List<String[]> encoded = new ArrayList<>();
            for (String[] field : fields) {
                String name = field.length > 0 ? field[0] : "";
                String kind = field.length > 1 ? field[1] : "fixed";
                String value = field.length > 2 ? field[2] : "";
                if (name.isEmpty()) {
                    continue;
                }
                if ("user".equals(kind)) {
                    value = username;
                } else if ("pass".equals(kind)) {
                    value = password;
                }
                encoded.add(new String[]{name, value});
            }

            URI target = actionUri;
            HttpRequest.Builder builder = HttpRequest.newBuilder(target)
                    .timeout(Duration.ofMillis(timeoutMs))
                    .header("User-Agent", cfg.getOrDefault("userAgent", "LeakForce/1.0"))
                    .header("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.8");

            String referer = cfg.getOrDefault("referer", "");
            if (!referer.isBlank()) {
                builder.header("Referer", referer);
            }

            if ("GET".equals(method)) {
                String query = encodeForm(encoded);
                if (!query.isEmpty()) {
                    String text = target.toString();
                    String sep = text.contains("?") ? "&" : "?";
                    builder = HttpRequest.newBuilder(URI.create(text + sep + query))
                            .timeout(Duration.ofMillis(timeoutMs))
                            .header("User-Agent", cfg.getOrDefault("userAgent", "LeakForce/1.0"))
                            .header("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
                            .header("Accept-Language", "en-US,en;q=0.8");
                    if (!referer.isBlank()) {
                        builder.header("Referer", referer);
                    }
                }
                builder.GET();
            } else {
                String bodyText = encodeForm(encoded);
                builder.header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(bodyText, StandardCharsets.UTF_8));
            }

            HttpResponse<String> response = client.send(
                    builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

            status = response.statusCode();
            statusText = String.valueOf(status);
            location = response.headers().firstValue("location").orElse("");
            String fullBody = response.body() == null ? "" : response.body();
            body = fullBody.length() > 4000 ? fullBody.substring(0, 4000) : fullBody;
        } catch (Exception exc) {
            error = String.valueOf(exc.getMessage() == null ? exc : exc.getMessage());
            if (error.length() > 300) {
                error = error.substring(0, 300);
            }
        }

        long elapsedMs = System.currentTimeMillis() - started;
        COMPLETED.incrementAndGet();

        OUT.println("{\"type\":\"attempt\",\"n\":" + number
                + ",\"username\":\"" + escape(username)
                + "\",\"password\":\"" + escape(password)
                + "\",\"status\":" + status
                + ",\"statusText\":\"" + escape(statusText)
                + "\",\"location\":\"" + escape(location)
                + "\",\"bodyLen\":" + body.length()
                + ",\"body\":\"" + escape(body)
                + "\",\"error\":\"" + escape(error)
                + "\",\"elapsedMs\":" + elapsedMs + "}");
        OUT.flush();
    }

    /** Reserve a global request slot so the overall rate never exceeds 1/delayMs. */
    private static boolean waitForRateSlot(int delayMs) {
        long wait;
        synchronized (RATE_LOCK) {
            long now = System.currentTimeMillis();
            long slot = Math.max(now, nextSlot);
            nextSlot = slot + Math.max(0, delayMs);
            wait = slot - now;
        }
        try {
            if (wait > 0) {
                Thread.sleep(wait);
            }
            return !STOP.get();
        } catch (InterruptedException exc) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String encodeForm(List<String[]> fields) {
        StringBuilder sb = new StringBuilder();
        for (String[] field : fields) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(field[0], StandardCharsets.UTF_8));
            sb.append('=');
            sb.append(URLEncoder.encode(field[1] == null ? "" : field[1], StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private static void seedCookies(CookieManager manager, URI uri, String header) {
        for (String pair : header.split(";")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (name.isEmpty()) {
                continue;
            }
            try {
                manager.getCookieStore().add(uri, new HttpCookie(name, value));
            } catch (Exception ignored) {
                // Ignore malformed cookies from the target.
            }
        }
    }

    private static Map<String, String> readTsvMap(String path) throws Exception {
        Map<String, String> map = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of(path), StandardCharsets.UTF_8)) {
            if (line.isEmpty()) {
                continue;
            }
            int tab = line.indexOf('\t');
            if (tab < 0) {
                continue;
            }
            map.put(line.substring(0, tab).trim(), line.substring(tab + 1));
        }
        return map;
    }

    private static List<String[]> readTsvRows(String path) throws Exception {
        List<String[]> rows = new ArrayList<>();
        if (path == null || path.isBlank()) {
            return rows;
        }
        for (String line : Files.readAllLines(Path.of(path), StandardCharsets.UTF_8)) {
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\t", -1);
            if (parts.length >= 2) {
                rows.add(parts);
            }
        }
        return rows;
    }

    private static int intValue(String text, int fallback) {
        try {
            return Integer.parseInt(text.trim());
        } catch (Exception exc) {
            return fallback;
        }
    }

    private static String escape(String text) {
        if (text == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(text.length() + 16);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
