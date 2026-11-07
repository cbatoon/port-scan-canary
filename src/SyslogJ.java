import java.io.BufferedWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SyslogJ - a minimal UDP syslog collector.
 *
 * Receives syslog datagrams, prints each one with the sender's address and the
 * time it arrived, and appends it to a log file. Messages that start with an
 * RFC 3164 / 5424 priority (e.g. "<36>") are decoded into facility and severity.
 *
 * Usage:
 *   java SyslogJ                          listen on UDP 514, log to log.txt
 *   java SyslogJ --port 5514 --log scans.log
 */
public class SyslogJ {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern PRI = Pattern.compile("^<(\\d{1,3})>");

    private static final String[] SEVERITIES = {
            "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
    };
    private static final String[] FACILITIES = {
            "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
            "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
            "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"
    };

    public static void main(String[] args) {
        int port = 514;
        Path logFile = Path.of("log.txt");

        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--port" -> port = Integer.parseInt(args[++i]);
                    case "--log" -> logFile = Path.of(args[++i]);
                    case "-h", "--help" -> { printUsage(); return; }
                    default -> throw new IllegalArgumentException("unknown option " + args[i]);
                }
            }
            if (port < 1 || port > 65535) throw new IllegalArgumentException("port out of range");
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            printUsage();
            System.exit(1);
        }

        try (DatagramSocket socket = new DatagramSocket(port);
             BufferedWriter writer = Files.newBufferedWriter(logFile, StandardCharsets.UTF_8,
                     StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {

            System.out.println("SyslogJ listening on UDP " + port + ", writing to " + logFile.toAbsolutePath());
            byte[] buffer = new byte[8192]; // RFC 5424 receivers should accept at least 2048 bytes

            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                String message = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8)
                        .stripTrailing();
                String source = packet.getAddress().getHostAddress() + ":" + packet.getPort();
                String received = LocalDateTime.now().format(TIME_FORMAT);

                String line = received + " - " + source + " - " + describePriority(message) + stripPriority(message);
                System.out.println(line);
                writer.write(line);
                writer.newLine();
                writer.flush();
            }
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage()
                    + (port < 1024 ? " (ports below 1024 may need administrator/root privileges)" : ""));
            System.exit(2);
        }
    }

    /** "<36>..." becomes "[auth.warning] "; messages without a priority get no label. */
    static String describePriority(String message) {
        Matcher m = PRI.matcher(message);
        if (!m.find()) return "";
        int pri = Integer.parseInt(m.group(1));
        if (pri > 191) return "";
        int facility = pri / 8;
        int severity = pri % 8;
        return "[" + FACILITIES[facility] + "." + SEVERITIES[severity] + "] ";
    }

    static String stripPriority(String message) {
        Matcher m = PRI.matcher(message);
        return m.find() && Integer.parseInt(m.group(1)) <= 191 ? message.substring(m.end()) : message;
    }

    private static void printUsage() {
        System.err.println("""
                Usage: java SyslogJ [--port PORT] [--log FILE]
                  --port PORT   UDP port to listen on (default 514)
                  --log FILE    file to append received messages to (default log.txt)""");
    }
}
