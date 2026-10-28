import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class ScanDatabase {

    private final String url;

    public ScanDatabase(String path) throws SQLException {

        this.url = "jdbc:sqlite:" + path;

        try (Connection connection = connect();
             Statement statement = connection.createStatement()) {

            statement.execute(
                    "CREATE TABLE IF NOT EXISTS scans ("
                    + " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + " share_id TEXT UNIQUE,"
                    + " filename TEXT NOT NULL,"
                    + " size INTEGER NOT NULL,"
                    + " hash TEXT,"
                    + " risk TEXT NOT NULL,"
                    + " reasons TEXT,"
                    + " timestamp TEXT NOT NULL)"
            );

            statement.execute(
                    "CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(hash)"
            );
        }
    }

    public synchronized void save(ScanRecord record) throws SQLException {

        String sql = "INSERT INTO scans"
                + " (share_id, filename, size, hash, risk, reasons, timestamp)"
                + " VALUES (?, ?, ?, ?, ?, ?, ?)";

        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, record.getShareId());
            statement.setString(2, record.getFilename());
            statement.setLong(3, record.getSize());
            statement.setString(4, record.getHash());
            statement.setString(5, record.getRisk());
            statement.setString(6, record.getReasons());
            statement.setString(7, record.getTimestamp());
            statement.executeUpdate();
        }
    }

    public ScanRecord findByShareId(String shareId) throws SQLException {

        List<ScanRecord> records = query(
                "SELECT * FROM scans WHERE share_id = ?", shareId
        );

        return records.isEmpty() ? null : records.get(0);
    }

    public List<ScanRecord> findByHash(String hash) throws SQLException {
        return query(
                "SELECT * FROM scans WHERE hash = ? ORDER BY id DESC", hash
        );
    }

    public List<ScanRecord> findRecent(int limit) throws SQLException {
        return query(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", limit
        );
    }

    private List<ScanRecord> query(String sql, Object parameter)
            throws SQLException {

        List<ScanRecord> records = new ArrayList<>();

        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setObject(1, parameter);

            try (ResultSet rows = statement.executeQuery()) {

                while (rows.next()) {

                    ScanRecord record = new ScanRecord(
                            rows.getString("filename"),
                            rows.getLong("size"),
                            rows.getString("hash"),
                            rows.getString("risk"),
                            rows.getString("reasons"),
                            rows.getString("timestamp")
                    );

                    record.setShareId(rows.getString("share_id"));
                    records.add(record);
                }
            }
        }

        return records;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(url);
    }
}
