public class ScanRecord {

    private String filename;
    private long size;
    private String hash;
    private String risk;
    private String reasons;
    private String timestamp;
    private String shareId;

    public ScanRecord(
            String filename,
            long size,
            String hash,
            String risk,
            String reasons,
            String timestamp) {

        this.filename = filename;
        this.size = size;
        this.hash = hash;
        this.risk = risk;
        this.reasons = reasons;
        this.timestamp = timestamp;
    }

    public String getFilename() {
        return filename;
    }

    public long getSize() {
        return size;
    }

    public String getHash() {
        return hash;
    }

    public String getRisk() {
        return risk;
    }

    public String getReasons() {
        return reasons;
    }

    public String getTimestamp() {
        return timestamp;
    }

    // Null when the file was blocked and not stored for sharing.
    public String getShareId() {
        return shareId;
    }

    public void setShareId(String shareId) {
        this.shareId = shareId;
    }
}
