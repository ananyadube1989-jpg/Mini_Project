import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FileScanner {

    public static final long MAX_FILE_SIZE = 100L * 1024 * 1024;

    // SHA-256 hashes of known malicious files. The EICAR entry is the
    // industry-standard harmless antivirus test file, useful for demos.
    private static final List<String> KNOWN_MALWARE_HASHES = Arrays.asList(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    );

    private static final List<String> SUPPORTED_EXTENSIONS = Arrays.asList(
            "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs",
            "js", "jar", "zip", "pdf", "doc", "docx", "xls",
            "xlsx", "jpg", "jpeg", "png", "txt"
    );

    private static final List<String> SUSPICIOUS_EXTENSIONS = Arrays.asList(
            "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs",
            "js", "jar"
    );

    private static final List<String> SUSPICIOUS_WORDS = Arrays.asList(
            "crack", "keygen", "payload", "hack",
            "malware", "trojan", "virus", "ransom"
    );

    public ScanRecord scan(File file) {
        return scan(file, file == null ? "" : file.getName());
    }

    // Uploaded files are stored under temporary names, so the web server
    // passes the user's original filename for the name-based checks.
    public ScanRecord scan(File file, String originalName) {

        String filename = originalName == null ? "" : originalName;
        long size = file == null ? 0 : file.length();

        try {

            if (file == null) {
                return error(filename, size, "No file selected");
            }

            if (!file.exists()) {
                return error(filename, size, "File does not exist");
            }

            if (!file.isFile()) {
                return error(filename, size, "Selected path is not a file");
            }

            if (size > MAX_FILE_SIZE) {
                return error(filename, size, "File too large");
            }

            String extension = getExtension(filename);

            if (!SUPPORTED_EXTENSIONS.contains(extension)) {
                return error(filename, size, "Unsupported file type");
            }

            String hash = calculateSHA256(file);

            List<String> reasons = new ArrayList<>();
            int score = 0;

            if (KNOWN_MALWARE_HASHES.contains(hash)) {
                reasons.add("Matches a known malware hash");
                score += 100;
            }

            if (checkSuspiciousExtension(extension)) {
                reasons.add("Suspicious executable or script extension");
                score += 10;
            }

            if (checkSuspiciousFilename(filename)) {
                reasons.add("Suspicious filename");
                score += 30;
            }

            if (checkDoubleExtension(filename)) {
                reasons.add("Double extension detected");
                score += 50;
            }

            if (checkUnexpectedExecutableHeader(file, extension)) {
                reasons.add("Unexpected executable header");
                score += 60;
            }

            String risk = getRisk(score);
            String reasonText = String.join(", ", reasons);

            return new ScanRecord(
                    filename,
                    size,
                    hash,
                    risk,
                    reasonText,
                    LocalDateTime.now().toString()
            );

        } catch (Exception e) {

            return error(
                    filename,
                    size,
                    "Could not read file: " + e.getMessage()
            );
        }
    }

    private ScanRecord error(
            String filename,
            long size,
            String message) {

        return new ScanRecord(
                filename,
                size,
                "",
                "ERROR",
                message,
                LocalDateTime.now().toString()
        );
    }

    private String getExtension(String filename) {

        int index = filename.lastIndexOf('.');

        if (index == -1) {
            return "";
        }

        return filename.substring(index + 1).toLowerCase();
    }

    private boolean checkSuspiciousExtension(String extension) {
        return SUSPICIOUS_EXTENSIONS.contains(extension);
    }

    private boolean checkSuspiciousFilename(String filename) {

        String name = filename.toLowerCase();

        for (String word : SUSPICIOUS_WORDS) {

            if (name.contains(word)) {
                return true;
            }
        }

        return false;
    }

    private boolean checkDoubleExtension(String filename) {

        String name = filename.toLowerCase();

        return name.matches(
                ".*\\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)\\.(exe|dll|scr|bat|cmd|js|ps1|vbs|jar)$"
        );
    }

    private boolean checkUnexpectedExecutableHeader(
            File file,
            String extension) {

        if (extension.equals("exe") ||
            extension.equals("dll") ||
            extension.equals("scr")) {
            return false;
        }

        try (FileInputStream input = new FileInputStream(file)) {

            int first = input.read();
            int second = input.read();

            return first == 'M' && second == 'Z';

        } catch (Exception e) {

            return false;
        }
    }

    private String calculateSHA256(File file) throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        try (FileInputStream input =
                     new FileInputStream(file)) {

            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = input.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }

        byte[] hash = digest.digest();

        StringBuilder result = new StringBuilder();

        for (byte b : hash) {
            result.append(String.format("%02x", b));
        }

        return result.toString();
    }

    private String getRisk(int score) {

        if (score == 0) {
            return "CLEAN";
        }

        if (score <= 20) {
            return "LOW";
        }

        if (score <= 50) {
            return "MEDIUM";
        }

        return "HIGH";
    }
}
