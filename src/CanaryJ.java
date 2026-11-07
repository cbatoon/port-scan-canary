import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * CanaryJ - a lightweight port-scan canary.
 *
 * Opens decoy TCP and UDP listeners on commonly targeted ports. Any connection
 * or datagram that reaches one of them is treated as a sign of reconnaissance
 * and reported to the console and, optionally, to a syslog server over UDP.
 *
 * Usage:
 *   java CanaryJ                                  default ports (TCP+UDP 22, 23, 80, 443, 3389)
 *   java CanaryJ tcp 22 80 udp 53 161             custom ports and protocols
 *   java CanaryJ params.in                        read the same tokens from a file
 *   java CanaryJ --syslog 10.0.20.5:514 tcp 22    forward alerts to a syslog server
 *   java CanaryJ --no-syslog                      console only
 */
public class CanaryJ {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final int[] DEFAULT_PORTS = {22, 23, 80, 443, 3389};

    // Syslog PRI value: facility 4 (security/auth) * 8 + severity 4 (warning) = 36
    private static final int SYSLOG_PRI_ALERT = 36;
    // facility 4 * 8 + severity 6 (informational) = 38
    private static final int SYSLOG_PRI_INFO = 38;

    /** One message waiting to be written; the writer thread is the only consumer. */
    private record Event(int priority, String text) { }

    // Listener threads only enqueue. A single writer thread drains the queue, so
    // console output and syslog forwarding are sequential and never interleave.
    private static final BlockingQueue<Event> events = new LinkedBlockingQueue<>();

    private static InetSocketAddress syslogTarget = new InetSocketAddress("127.0.0.1", 514);

    public static void main(String[] args) {
        for (String arg : args) {
            if (arg.equals("-h") || arg.equals("--help")) {
                printUsage();
                return;
            }
        }

        Config config;
        try {
            config = Config.parse(args);
        } catch (IllegalArgumentException | IOException e) {
            System.err.println("Error: " + e.getMessage());
            printUsage();
            System.exit(1);
            return;
        }
        syslogTarget = config.syslogTarget;

        startWriter();
        info("CanaryJ starting"
                + (syslogTarget == null ? " (syslog forwarding off)"
                                        : " (forwarding to syslog " + describe(syslogTarget) + ")"));

        int started = 0;
        for (int port : config.tcpPorts) {
            if (startTcpListener(port)) started++;
        }
        for (int port : config.udpPorts) {
            if (forwardsToItself(port)) {
                info("Skipping UDP port " + port + ": it is the local syslog destination");
                continue;
            }
            if (startUdpListener(port)) started++;
        }

        if (started == 0) {
            info("No listeners could be started; exiting.");
            // give the writer a moment to flush
            try { Thread.sleep(250); } catch (InterruptedException ignored) { }
            System.exit(2);
        }
    }

    /** Listening on the port we forward to on this machine would alert on our own messages forever. */
    private static boolean forwardsToItself(int udpPort) {
        if (syslogTarget == null || syslogTarget.getPort() != udpPort) return false;
        InetAddress target = syslogTarget.getAddress();
        if (target == null) return false;
        try {
            return target.isLoopbackAddress() || target.isAnyLocalAddress()
                    || java.net.NetworkInterface.getByInetAddress(target) != null;
        } catch (IOException e) {
            return false;
        }
    }

    // ---------------------------------------------------------------- listeners

    /**
     * Binds the port once and hands the bound socket to its thread. If the port
     * is already in use by another service the bind fails and we skip it, which
     * avoids the race of "test bind, close, bind again".
     */
    private static boolean startTcpListener(int port) {
        ServerSocket server;
        try {
            server = new ServerSocket(port);
        } catch (IOException e) {
            info("TCP port " + port + " is already in use or not permitted; skipping");
            return false;
        }
        info("Listening on TCP port " + port);
        Thread t = new Thread(() -> runTcp(server, port), "tcp-" + port);
        t.setDaemon(false);
        t.start();
        return true;
    }

    private static void runTcp(ServerSocket server, int port) {
        try (server) {
            while (true) {
                try (Socket client = server.accept()) {
                    InetSocketAddress remote = (InetSocketAddress) client.getRemoteSocketAddress();
                    alert(remote, "TCP", port);
                }
            }
        } catch (IOException e) {
            info("TCP listener on port " + port + " stopped: " + e.getMessage());
        }
    }

    private static boolean startUdpListener(int port) {
        DatagramSocket socket;
        try {
            socket = new DatagramSocket(port);
        } catch (IOException e) {
            info("UDP port " + port + " is already in use or not permitted; skipping");
            return false;
        }
        info("Listening on UDP port " + port);
        Thread t = new Thread(() -> runUdp(socket, port), "udp-" + port);
        t.start();
        return true;
    }

    private static void runUdp(DatagramSocket socket, int port) {
        byte[] buffer = new byte[2048];
        try (socket) {
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                alert(new InetSocketAddress(packet.getAddress(), packet.getPort()), "UDP", port);
            }
        } catch (IOException e) {
            info("UDP listener on port " + port + " stopped: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ output

    private static void alert(InetSocketAddress source, String protocol, int port) {
        events.add(new Event(SYSLOG_PRI_ALERT,
                describe(source) + " is scanning " + protocol + " port " + port + "."));
    }

    private static void info(String text) {
        events.add(new Event(SYSLOG_PRI_INFO, text));
    }

    private static void startWriter() {
        Thread writer = new Thread(() -> {
            DatagramSocket out = null;
            try {
                out = new DatagramSocket();
            } catch (IOException e) {
                System.out.println(timestamp() + " - Could not open syslog socket: " + e.getMessage());
            }
            while (true) {
                Event event;
                try {
                    event = events.take();
                } catch (InterruptedException e) {
                    return;
                }
                String line = timestamp() + " - " + event.text();
                System.out.println(line);
                if (out != null && syslogTarget != null) {
                    forward(out, event);
                }
            }
        }, "writer");
        writer.setDaemon(true);
        writer.start();
    }

    /** Sends an RFC 3164-style message: "<PRI>TAG: text", UTF-8 encoded. */
    private static void forward(DatagramSocket out, Event event) {
        byte[] payload = ("<" + event.priority() + ">CanaryJ: " + timestamp() + " - " + event.text())
                .getBytes(StandardCharsets.UTF_8);
        try {
            out.send(new DatagramPacket(payload, payload.length, syslogTarget));
        } catch (IOException e) {
            System.out.println(timestamp() + " - Forwarding to syslog failed: " + e.getMessage());
        }
    }

    private static String timestamp() {
        return LocalDateTime.now().format(TIME_FORMAT);
    }

    private static String describe(InetSocketAddress address) {
        InetAddress ip = address.getAddress();
        String host = ip != null ? ip.getHostAddress() : address.getHostString();
        if (host.contains(":")) host = "[" + host + "]"; // IPv6
        return host + ":" + address.getPort();
    }

    private static void printUsage() {
        System.err.println("""
                Usage:
                  java CanaryJ [--syslog host[:port] | --no-syslog] [tcp PORT...] [udp PORT...]
                  java CanaryJ [--syslog host[:port] | --no-syslog] params.in

                With no ports given, listens on TCP and UDP 22, 23, 80, 443 and 3389.
                A params file holds the same tokens, separated by spaces or new lines;
                anything after # on a line is a comment.""");
    }

    // ------------------------------------------------------------------ config

    private static final class Config {
        final Set<Integer> tcpPorts = new LinkedHashSet<>();
        final Set<Integer> udpPorts = new LinkedHashSet<>();
        InetSocketAddress syslogTarget = new InetSocketAddress("127.0.0.1", 514);

        static Config parse(String[] args) throws IOException {
            // Any argument that names an existing file is read as a params file.
            // File tokens are applied first so command-line options override them.
            List<String> fromFiles = new ArrayList<>();
            List<String> fromCommandLine = new ArrayList<>();
            for (String token : args) {
                if (!token.startsWith("-") && !isProtocol(token) && !isNumber(token)
                        && Files.isRegularFile(Path.of(token))) {
                    fromFiles.addAll(readParamsFile(Path.of(token)));
                } else {
                    fromCommandLine.add(token);
                }
            }
            List<String> expanded = new ArrayList<>(fromFiles);
            if (!fromFiles.isEmpty() && !fromCommandLine.isEmpty()
                    && !isProtocol(fromCommandLine.get(0)) && !fromCommandLine.get(0).startsWith("-")) {
                throw new IllegalArgumentException(
                        "port '" + fromCommandLine.get(0) + "' must follow 'tcp' or 'udp'");
            }
            expanded.addAll(fromCommandLine);

            Config config = new Config();
            String protocol = null;
            for (int i = 0; i < expanded.size(); i++) {
                String token = expanded.get(i);
                String lower = token.toLowerCase();
                switch (lower) {
                    case "--no-syslog" -> config.syslogTarget = null;
                    case "--syslog" -> {
                        if (i + 1 >= expanded.size()) {
                            throw new IllegalArgumentException("--syslog needs host[:port]");
                        }
                        config.syslogTarget = parseHostPort(expanded.get(++i));
                    }
                    case "tcp", "udp" -> protocol = lower;
                    default -> {
                        if (protocol == null) {
                            throw new IllegalArgumentException(
                                    "port '" + token + "' must follow 'tcp' or 'udp'");
                        }
                        int port = parsePort(token);
                        (protocol.equals("tcp") ? config.tcpPorts : config.udpPorts).add(port);
                    }
                }
            }

            if (config.tcpPorts.isEmpty() && config.udpPorts.isEmpty()) {
                for (int port : DEFAULT_PORTS) {
                    config.tcpPorts.add(port);
                    config.udpPorts.add(port);
                }
            }
            return config;
        }

        private static List<String> readParamsFile(Path file) throws IOException {
            List<String> result = new ArrayList<>();
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                int hash = line.indexOf('#');
                if (hash >= 0) line = line.substring(0, hash);
                for (String token : line.trim().split("[\\s,]+")) {
                    if (!token.isEmpty()) result.add(token);
                }
            }
            return result;
        }

        private static InetSocketAddress parseHostPort(String value) {
            String host = value;
            int port = 514;
            int colon = value.lastIndexOf(':');
            if (colon > 0 && value.indexOf(':') == colon) { // host:port (not bare IPv6)
                host = value.substring(0, colon);
                port = parsePort(value.substring(colon + 1));
            }
            return new InetSocketAddress(host, port);
        }

        private static int parsePort(String value) {
            try {
                int port = Integer.parseInt(value);
                if (port < 1 || port > 65535) throw new NumberFormatException();
                return port;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("'" + value + "' is not a valid port (1-65535)");
            }
        }

        private static boolean isProtocol(String s) {
            return s.equalsIgnoreCase("tcp") || s.equalsIgnoreCase("udp");
        }

        private static boolean isNumber(String s) {
            return s.chars().allMatch(Character::isDigit) && !s.isEmpty();
        }
    }
}
