import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public class WebServer {

    private static final int PORT = 8080;

    private static final Path WEB_DIR = Paths.get("web");
    private static final Path UPLOAD_DIR = Paths.get("uploads");

    // Only these files are served, so no request path can reach other files.
    private static final Map<String, String> STATIC_FILES = Map.of(
            "/", "index.html",
            "/index.html", "index.html",
            "/style.css", "style.css",
            "/app.js", "app.js"
    );

    private final FileScanner scanner = new FileScanner();
    private final ScanDatabase database;
    private final SecureRandom random = new SecureRandom();

    public WebServer(ScanDatabase database) {
        this.database = database;
    }

    public static void main(String[] args) throws Exception {

        Files.createDirectories(UPLOAD_DIR);

        WebServer app = new WebServer(new ScanDatabase("scans.db"));
        app.start();
    }

    private void start() throws IOException {

        // Bound to localhost only: this is a local demo, not a public server.
        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", PORT), 0
        );

        server.createContext("/", exchange -> handle(exchange, this::serveStatic));
        server.createContext("/api/scan", exchange -> handle(exchange, this::scanUpload));
        server.createContext("/api/history", exchange -> handle(exchange, this::history));
        server.createContext("/share/", exchange -> handle(exchange, this::sharePage));
        server.createContext("/download/", exchange -> handle(exchange, this::download));

        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();

        System.out.println("Malware File Scanner running at http://localhost:" + PORT);
        System.out.println("Press Ctrl+C to stop.");
    }

    private interface Handler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private void handle(HttpExchange exchange, Handler handler) throws IOException {

        try {
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            handler.handle(exchange);
        } catch (Exception e) {
            e.printStackTrace();
            sendText(exchange, 500, "text/plain", "Internal server error");
        } finally {
            exchange.close();
        }
    }

    // ---------- Static pages ----------

    private void serveStatic(HttpExchange exchange) throws IOException {

        String file = STATIC_FILES.get(exchange.getRequestURI().getPath());

        if (file == null) {
            sendText(exchange, 404, "text/plain", "Not found");
            return;
        }

        String type = file.endsWith(".css") ? "text/css"
                : file.endsWith(".js") ? "application/javascript"
                : "text/html";

        byte[] body = Files.readAllBytes(WEB_DIR.resolve(file));
        send(exchange, 200, type + "; charset=utf-8", body);
    }

    // ---------- Upload and scan ----------

    private void scanUpload(HttpExchange exchange) throws Exception {

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendText(exchange, 405, "text/plain", "Use POST");
            return;
        }

        String header = exchange.getRequestHeaders().getFirst("X-Filename");
        String filename = sanitizeFilename(
                header == null ? "" : URLDecoder.decode(header, StandardCharsets.UTF_8)
        );

        Path temp = Files.createTempFile(UPLOAD_DIR, "upload-", ".tmp");

        try {
            // Read at most one byte over the limit so oversized uploads are
            // detected without writing the whole thing to disk.
            try (InputStream input = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(temp)) {
                copyWithLimit(input, output, FileScanner.MAX_FILE_SIZE + 1);
            }

            ScanRecord record = scanner.scan(temp.toFile(), filename);

            List<ScanRecord> previous = record.getHash().isEmpty()
                    ? List.of()
                    : database.findByHash(record.getHash());

            boolean blocked = record.getRisk().equals("HIGH")
                    || record.getRisk().equals("ERROR");

            if (!blocked) {
                String shareId = newShareId();
                Files.move(temp, UPLOAD_DIR.resolve(shareId));
                record.setShareId(shareId);
            }

            database.save(record);

            String json = "{"
                    + field("filename", record.getFilename()) + ","
                    + "\"size\":" + record.getSize() + ","
                    + field("hash", record.getHash()) + ","
                    + field("risk", record.getRisk()) + ","
                    + field("reasons", record.getReasons()) + ","
                    + field("timestamp", record.getTimestamp()) + ","
                    + field("shareId", record.getShareId()) + ","
                    + "\"blocked\":" + blocked + ","
                    + "\"previousScans\":" + previous.size() + ","
                    + field("previousRisk", previous.isEmpty() ? null : previous.get(0).getRisk())
                    + "}";

            sendText(exchange, 200, "application/json", json);

        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private void history(HttpExchange exchange) throws Exception {

        StringBuilder json = new StringBuilder("[");

        for (ScanRecord record : database.findRecent(100)) {

            if (json.length() > 1) {
                json.append(",");
            }

            json.append("{")
                    .append(field("filename", record.getFilename())).append(",")
                    .append("\"size\":").append(record.getSize()).append(",")
                    .append(field("hash", record.getHash())).append(",")
                    .append(field("risk", record.getRisk())).append(",")
                    .append(field("reasons", record.getReasons())).append(",")
                    .append(field("timestamp", record.getTimestamp())).append(",")
                    .append(field("shareId", record.getShareId()))
                    .append("}");
        }

        json.append("]");
        sendText(exchange, 200, "application/json", json.toString());
    }

    // ---------- Sharing ----------

    private void sharePage(HttpExchange exchange) throws Exception {

        ScanRecord record = findShared(exchange, "/share/");

        if (record == null) {
            sendText(exchange, 404, "text/html",
                    page("File not found", "<p>This share link is invalid or the file was removed.</p>"));
            return;
        }

        String risk = record.getRisk();
        String warning = risk.equals("CLEAN")
                ? "<p class=\"note ok\">No warning signs were found in this file.</p>"
                : "<p class=\"note warn\">This file has warning signs. Only open it if you trust the sender.</p>";

        String body = "<div class=\"card\">"
                + "<h2>" + html(record.getFilename()) + "</h2>"
                + "<span class=\"badge " + html(risk) + "\">" + html(risk) + "</span>"
                + warning
                + "<dl>"
                + "<dt>Size</dt><dd>" + formatSize(record.getSize()) + "</dd>"
                + "<dt>SHA-256</dt><dd class=\"hash\">" + html(record.getHash()) + "</dd>"
                + "<dt>Reasons</dt><dd>" + html(record.getReasons().isEmpty() ? "None" : record.getReasons()) + "</dd>"
                + "<dt>Scanned</dt><dd>" + html(record.getTimestamp()) + "</dd>"
                + "</dl>"
                + "<a class=\"button\" href=\"/download/" + html(record.getShareId()) + "\">Download file</a>"
                + "</div>";

        sendText(exchange, 200, "text/html", page("Shared file", body));
    }

    private void download(HttpExchange exchange) throws Exception {

        ScanRecord record = findShared(exchange, "/download/");

        if (record == null) {
            sendText(exchange, 404, "text/plain", "File not found");
            return;
        }

        Path file = UPLOAD_DIR.resolve(record.getShareId());
        String name = record.getFilename();
        String asciiName = name.replaceAll("[^A-Za-z0-9._ -]", "_");

        exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
        exchange.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"" + asciiName + "\"; filename*=UTF-8''"
                + URLEncoder.encode(name, StandardCharsets.UTF_8).replace("+", "%20"));

        exchange.sendResponseHeaders(200, Files.size(file));

        try (OutputStream output = exchange.getResponseBody()) {
            Files.copy(file, output);
        }
    }

    // Share IDs are random hex strings; anything else is rejected before
    // touching the database or the upload folder.
    private ScanRecord findShared(HttpExchange exchange, String prefix) throws Exception {

        String shareId = exchange.getRequestURI().getPath().substring(prefix.length());

        if (!shareId.matches("[0-9a-f]{32}")) {
            return null;
        }

        ScanRecord record = database.findByShareId(shareId);

        if (record == null || !Files.exists(UPLOAD_DIR.resolve(shareId))) {
            return null;
        }

        return record;
    }

    private String newShareId() {

        byte[] bytes = new byte[16];
        random.nextBytes(bytes);

        StringBuilder id = new StringBuilder();

        for (byte b : bytes) {
            id.append(String.format("%02x", b));
        }

        return id.toString();
    }

    // ---------- Helpers ----------

    // Keeps only the last path component so names like "../../evil.exe"
    // cannot point outside the upload folder, and strips control characters.
    private static String sanitizeFilename(String name) {

        String clean = name.substring(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1)
                .replaceAll("[\\p{Cntrl}]", "")
                .trim();

        if (clean.length() > 255) {
            clean = clean.substring(clean.length() - 255);
        }

        return clean.isEmpty() ? "unnamed" : clean;
    }

    private static void copyWithLimit(InputStream input, OutputStream output, long limit)
            throws IOException {

        byte[] buffer = new byte[8192];
        long total = 0;
        int read;

        while (total < limit && (read = input.read(buffer, 0, (int) Math.min(buffer.length, limit - total))) != -1) {
            output.write(buffer, 0, read);
            total += read;
        }
    }

    private static String page(String title, String body) {
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<title>" + html(title) + "</title>"
                + "<link rel=\"stylesheet\" href=\"/style.css\"></head><body>"
                + "<header><h1>🛡️ Malware File Scanner</h1><a href=\"/\">Upload a file</a></header>"
                + "<main>" + body + "</main></body></html>";
    }

    private static String formatSize(long bytes) {

        if (bytes < 1024) {
            return bytes + " B";
        }

        if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        }

        return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }

    private static String html(String text) {
        return text == null ? "" : text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String field(String name, String value) {
        return "\"" + name + "\":" + json(value);
    }

    private static String json(String text) {

        if (text == null) {
            return "null";
        }

        StringBuilder out = new StringBuilder("\"");

        for (char c : text.toCharArray()) {
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }

        return out.append("\"").toString();
    }

    private static void sendText(HttpExchange exchange, int status, String type, String text)
            throws IOException {
        send(exchange, status, type + "; charset=utf-8", text.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String type, byte[] body)
            throws IOException {

        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(status, body.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
        }
    }
}
