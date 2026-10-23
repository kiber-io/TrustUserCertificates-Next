import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Certificate validation and Android trust-store filenames; invoked through app_process. */
public final class CertTool {
    private static final int LIMIT = 65536;
    private static final String HOOKS = "@hooks";
    private static final Pattern NAME = Pattern.compile("[0-9a-f]{8}\\.[0-9]+");
    private static final Pattern PACKAGE = Pattern.compile("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+");
    private static final Pattern PEM = Pattern.compile(
        "\\s*-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/=\\r\\n\\t ]+)\\s*-----END CERTIFICATE-----\\s*");

    public static void main(String[] args) {
        try {
            if (args.length == 3 && args[0].equals("import")) {
                if (args[2].length() > ((LIMIT + 2) / 3) * 4) {
                    throw new IllegalArgumentException("Certificate exceeds 64 KiB");
                }
                X509Certificate cert = parse(Base64.getDecoder().decode(args[2]), true);
                System.out.println(store(directory(args[1]), cert));
            } else if (args.length == 2 && args[0].equals("list")) {
                System.out.println(list(directory(args[1])));
            } else if (args.length == 4 && args[0].equals("normalize")) {
                Map<String, Map<String, Integer>> rules = rules(new File(args[1]));
                validate(rules, directory(args[2]), appMap(new File(args[3])));
                System.out.print(normalized(rules));
            } else if (args.length == 3 && args[0].equals("drop-cert")) {
                if (!NAME.matcher(args[2]).matches()) throw new IllegalArgumentException("Invalid certificate name");
                Map<String, Map<String, Integer>> rules = rules(new File(args[1]));
                for (Map<String, Integer> names : rules.values()) names.remove(args[2]);
                System.out.print(normalized(rules));
            } else if (args.length == 8 && args[0].equals("prepare")) {
                File stock = directory(args[1]);
                File apex = args[2].equals("-") ? null : directory(args[2]);
                Map<String, Map<String, Integer>> rules = rules(new File(args[3]));
                File custom = directory(args[4]);
                Map<String, Integer> apps = appMap(new File(args[5]));
                validate(rules, custom, apps);
                File userBase = new File(args[6]);
                File dest = directory(args[7]);
                if (dest.list().length != 0) throw new IllegalArgumentException("Destination must be empty");
                Map<String, Integer> global = rules.get("@global");
                if (global == null) global = new TreeMap<>();
                Set<Integer> users = new TreeSet<>();
                for (int uid : apps.values()) users.add(uid / 100000);
                prepareStores(new File(dest, "global"), stock, apex, custom, global, userBase, users, ".trustusercerts-global");
                if (!global.isEmpty()) write(new File(dest, "global/enabled"), new byte[0]);
                if (!selected(global, 1).isEmpty()) write(new File(dest, "global/system-enabled"), new byte[0]);
                StringBuilder config = new StringBuilder();
                for (Map.Entry<String, Map<String, Integer>> rule : rules.entrySet()) {
                    if (rule.getKey().equals("@global")) continue;
                    Map<String, Integer> selected = new TreeMap<>(global);
                    selected.putAll(rule.getValue());
                    Integer hooks = selected.remove(HOOKS);
                    int uid = apps.get(rule.getKey());
                    String packageName = packageName(rule.getKey());
                    File app = new File(dest, "apps/" + (uid / 100000) + "/" + packageName);
                    prepareStores(app, stock, apex, custom,
                        selected, userBase, new TreeSet<>(Arrays.asList(uid / 100000)), ".trustusercerts-app");
                    if (hooks != null) write(new File(app, "hooks"), new byte[] {hooks.byteValue()});
                    config.append(uid).append(' ').append(packageName).append('\n');
                }
                write(new File(dest, "config"), config.toString().getBytes(StandardCharsets.UTF_8));
            } else if (args.length == 6 && args[0].equals("status")) {
                StringBuilder packages = new StringBuilder("[");
                StringBuilder assignments = new StringBuilder("{");
                StringBuilder hooks = new StringBuilder("{");
                Map<String, Map<String, Integer>> rules = rules(new File(args[3]));
                for (Map.Entry<String, Map<String, Integer>> rule : rules.entrySet()) {
                    if (rule.getKey().equals("@global")) continue;
                    if (packages.length() > 1) packages.append(',');
                    packages.append(quote(rule.getKey()));
                    String certs = jsonModes(rule.getValue());
                    if (!certs.equals("{}")) {
                        if (assignments.length() > 1) assignments.append(',');
                        assignments.append(quote(rule.getKey())).append(':').append(certs);
                    }
                    Integer flags = rule.getValue().get(HOOKS);
                    if (flags != null) {
                        if (hooks.length() > 1) hooks.append(',');
                        hooks.append(quote(rule.getKey())).append(":{\"disableCT\":")
                            .append((flags & 1) != 0).append(",\"trustUserCAs\":").append((flags & 2) != 0)
                            .append(",\"trustSystemCAs\":").append((flags & 4) != 0).append('}');
                    }
                }
                String log = "";
                if (new File(args[5]).isFile()) try (RandomAccessFile file = new RandomAccessFile(args[5], "r")) {
                    byte[] tail = new byte[(int) Math.min(file.length(), 16384)];
                    file.seek(file.length() - tail.length);
                    file.readFully(tail);
                    log = new String(tail, StandardCharsets.UTF_8);
                }
                System.out.println("{\"ready\":" + args[1].equals("true") + ",\"reason\":" + quote(args[2]) +
                    ",\"packages\":" + packages.append(']') + ",\"certificates\":" + list(directory(args[4])) +
                    ",\"assignments\":" + assignments.append('}') +
                    ",\"hooks\":" + hooks.append('}') +
                    ",\"globalCertificates\":" + jsonModes(rules.get("@global")) +
                    ",\"log\":" + quote(log) + "}");
            } else if (args.length == 4 && args[0].equals("merge")) {
                File stock = directory(args[1]);
                File custom = directory(args[2]);
                File dest = directory(args[3]);
                if (dest.list().length != 0) throw new IllegalArgumentException("Destination must be empty");
                for (File file : certificates(stock)) write(new File(dest, file.getName()), read(file));
                for (File file : certificates(custom)) store(dest, parse(read(file), true));
            } else {
                throw new IllegalArgumentException("Usage: import DIR BASE64 | list DIR | merge STOCK CUSTOM DEST | " +
                    "normalize RULES CUSTOM APPMAP | prepare STOCK APEX_OR_DASH RULES CUSTOM APPMAP USER_BASE_ROOT DEST | " +
                    "drop-cert RULES NAME | status READY REASON RULES CUSTOM LOG");
            }
        } catch (Exception e) {
            System.err.println("CertTool: " + e.getMessage());
            System.exit(1);
        }
    }

    private static Map<String, Map<String, Integer>> rules(File file) throws Exception {
        Map<String, Map<String, Integer>> rules = new TreeMap<>();
        if (!file.exists()) return rules;
        for (String line : new String(read(file), StandardCharsets.UTF_8).split("\\r?\\n")) {
            if (!line.matches("[\\x20-\\x7E\\t]*")) throw new IllegalArgumentException("Invalid character in certificate rule");
            if (line.trim().isEmpty()) continue;
            String[] parts = line.trim().split("[ \\t]+");
            if ((parts.length != 2 && parts.length != 3) ||
                (!parts[0].equals("@global") && !validKey(parts[0])) ||
                (!NAME.matcher(parts[1]).matches() && !parts[1].equals(HOOKS))) {
                throw new IllegalArgumentException("Invalid certificate rule: " + line);
            }
            boolean hook = parts[1].equals(HOOKS);
            if (hook && (parts.length != 3 || parts[0].equals("@global"))) {
                throw new IllegalArgumentException("Hooks require an app and explicit flags");
            }
            int mode = hook ? hookMode(parts[2]) : parts.length == 2 ? 1 : mode(parts[2]);
            if (parts[0].equals("@global") && mode == 0) {
                throw new IllegalArgumentException("Global Off is represented by removing the rule");
            }
            if (!rules.containsKey(parts[0])) rules.put(parts[0], new TreeMap<>());
            Integer previous = rules.get(parts[0]).put(parts[1], mode);
            if (previous != null && previous != mode) {
                throw new IllegalArgumentException("Conflicting rule modes for " + parts[0] + ": " + parts[1]);
            }
        }
        return rules;
    }

    private static String packageName(String key) {
        return key.substring(key.indexOf(':') + 1);
    }

    private static boolean validKey(String key) {
        int colon = key.indexOf(':');
        if (colon >= 0) {
            String user = key.substring(0, colon);
            if (!user.matches("[1-9][0-9]{0,4}") || Integer.parseInt(user) > 21474) return false;
        }
        String name = packageName(key);
        return name.length() <= 255 && PACKAGE.matcher(name).matches();
    }

    private static Map<String, Integer> appMap(File file) throws Exception {
        Map<String, Integer> apps = new TreeMap<>();
        for (String line : new String(read(file, 2 * 1024 * 1024), StandardCharsets.UTF_8).split("\\r?\\n")) {
            if (!line.matches("[\\x20-\\x7E\\t]*")) throw new IllegalArgumentException("Invalid character in installed-app record");
            if (line.trim().isEmpty()) continue;
            String[] parts = line.trim().split("[ \\t]+");
            if (parts.length != 2 || !parts[0].matches("[0-9]+")) {
                throw new IllegalArgumentException("Invalid installed-app record");
            }
            int uid = Integer.parseInt(parts[0]);
            if (uid % 100000 < 10000 || uid % 100000 >= 20000) continue;
            if (parts[1].length() > 255 || !PACKAGE.matcher(parts[1]).matches()) {
                throw new IllegalArgumentException("Invalid installed package");
            }
            String key = uid < 100000 ? parts[1] : (uid / 100000) + ":" + parts[1];
            Integer previous = apps.put(key, uid);
            if (previous != null && previous != uid) throw new IllegalArgumentException("Conflicting installed UID");
        }
        return apps;
    }

    private static void validate(Map<String, Map<String, Integer>> rules, File custom, Map<String, Integer> apps) throws Exception {
        Set<String> checked = new TreeSet<>();
        for (Map.Entry<String, Map<String, Integer>> rule : rules.entrySet()) {
            if (!rule.getKey().equals("@global") && !apps.containsKey(rule.getKey())) {
                throw new IllegalArgumentException("Package is not installed for the selected user: " + rule.getKey());
            }
            for (String name : rule.getValue().keySet()) {
                if (!name.equals(HOOKS) && checked.add(name)) parse(read(new File(custom, name)), true);
            }
        }
    }

    private static int mode(String value) {
        if (value.equals("off")) return 0;
        if (value.equals("system")) return 1;
        if (value.equals("user")) return 2;
        if (value.equals("both")) return 3;
        throw new IllegalArgumentException("Invalid certificate mode: " + value);
    }

    private static int hookMode(String value) {
        if (value.equals("ct")) return 1;
        if (value.equals("user")) return 2;
        if (value.equals("both")) return 3;
        if (value.equals("system")) return 4;
        if (value.equals("ct-system")) return 5;
        if (value.equals("user-system")) return 6;
        if (value.equals("all")) return 7;
        throw new IllegalArgumentException("Invalid hook flags: " + value);
    }

    private static String hookModeName(int flags) {
        return new String[]{"", "ct", "user", "both", "system", "ct-system", "user-system", "all"}[flags];
    }

    private static String modeName(int mode) {
        return mode == 0 ? "off" : mode == 1 ? "system" : mode == 2 ? "user" : "both";
    }

    private static String normalized(Map<String, Map<String, Integer>> rules) {
        StringBuilder text = new StringBuilder();
        for (Map.Entry<String, Map<String, Integer>> rule : rules.entrySet()) {
            for (Map.Entry<String, Integer> cert : rule.getValue().entrySet()) {
                text.append(rule.getKey()).append(' ').append(cert.getKey());
                if (cert.getKey().equals(HOOKS)) text.append(' ').append(hookModeName(cert.getValue()));
                else if (cert.getValue() != 1) text.append(' ').append(modeName(cert.getValue()));
                text.append('\n');
            }
        }
        return text.toString();
    }

    private static String jsonModes(Map<String, Integer> modes) {
        StringBuilder json = new StringBuilder("{");
        if (modes != null) for (Map.Entry<String, Integer> cert : modes.entrySet()) {
            if (cert.getKey().equals(HOOKS)) continue;
            if (json.length() > 1) json.append(',');
            json.append(quote(cert.getKey())).append(':').append(quote(modeName(cert.getValue())));
        }
        return json.append('}').toString();
    }

    private static Set<String> selected(Map<String, Integer> modes, int bit) {
        Set<String> selected = new TreeSet<>();
        for (Map.Entry<String, Integer> cert : modes.entrySet()) {
            if ((cert.getValue() & bit) != 0) selected.add(cert.getKey());
        }
        return selected;
    }

    private static void prepareStores(File root, File stock, File apex, File custom,
                                      Map<String, Integer> modes, File userBase, Set<Integer> users, String marker) throws Exception {
        Set<String> system = selected(modes, 1);
        prepareStore(new File(root, "system"), stock, custom, system, marker);
        if (apex != null) prepareStore(new File(root, "apex"), apex, custom, system, marker);
        Set<String> user = selected(modes, 2);
        if (!user.isEmpty()) for (int id : users) {
            File baseline = new File(userBase, id + "/cacerts-added");
            if (!baseline.getParentFile().isDirectory()) {
                throw new IllegalArgumentException("User certificate directory is unavailable for Android user " + id + ": " + baseline);
            }
            try {
                if (!Files.readAttributes(baseline.toPath(), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory()) {
                    throw new IllegalArgumentException("Invalid user certificate directory for Android user " + id + ": " + baseline);
                }
            } catch (NoSuchFileException absent) {
                baseline = null;
            }
            prepareStore(new File(root, "user/" + id), baseline, custom, user, marker);
        }
    }

    private static void prepareStore(File dest, File stock, File custom,
                                     Set<String> selected, String marker) throws Exception {
        if (!dest.mkdirs()) throw new IllegalArgumentException("Cannot create " + dest);
        if (stock != null) for (File file : certificates(stock)) write(new File(dest, file.getName()), read(file));
        for (String name : selected) store(dest, parse(read(new File(custom, name)), true));
        write(new File(dest, marker), new byte[0]);
    }

    private static String list(File dir) throws Exception {
        StringBuilder json = new StringBuilder("[");
        for (File file : certificates(dir)) {
            X509Certificate cert = parse(read(file), true);
            if (json.length() > 1) json.append(',');
            json.append("{\"name\":").append(quote(file.getName()))
                .append(",\"subject\":").append(quote(cert.getSubjectX500Principal().getName()))
                .append(",\"fingerprint\":").append(quote(fingerprint(cert))).append('}');
        }
        return json.append(']').toString();
    }

    private static File directory(String path) throws Exception {
        File dir = new File(path);
        if (!dir.isDirectory()) throw new IllegalArgumentException("Missing directory: " + path);
        return dir;
    }

    private static File[] certificates(File dir) throws Exception {
        File[] files = dir.listFiles((parent, name) -> NAME.matcher(name).matches());
        if (files == null) throw new IllegalArgumentException("Cannot read directory: " + dir);
        Arrays.sort(files);
        return files;
    }

    private static byte[] read(File file) throws Exception {
        return read(file, LIMIT);
    }

    private static byte[] read(File file, int limit) throws Exception {
        try (FileInputStream in = new FileInputStream(file);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int count;
            while ((count = in.read(buffer)) != -1) {
                if (out.size() + count > limit) throw new IllegalArgumentException("Input exceeds " + limit + " bytes: " + file);
                out.write(buffer, 0, count);
            }
            return out.toByteArray();
        }
    }

    private static X509Certificate parse(byte[] input, boolean requireCa) throws Exception {
        if (input.length == 0 || input.length > LIMIT) throw new IllegalArgumentException("Invalid certificate size");
        byte[] der = input;
        String text = new String(input, StandardCharsets.US_ASCII);
        if (text.trim().startsWith("-----")) {
            Matcher match = PEM.matcher(text);
            if (!match.matches()) throw new IllegalArgumentException("Expected exactly one PEM certificate");
            der = Base64.getDecoder().decode(match.group(1).replaceAll("\\s", ""));
        }
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(der));
        if (!Arrays.equals(der, cert.getEncoded())) {
            throw new IllegalArgumentException("Expected exactly one DER certificate without trailing data");
        }
        if (requireCa) {
            boolean[] usage = cert.getKeyUsage();
            if (cert.getBasicConstraints() < 0 || (usage != null && (usage.length <= 5 || !usage[5]))) {
                throw new IllegalArgumentException("Certificate must be a CA permitted to sign certificates");
            }
        }
        return cert;
    }

    private static String hash(X509Certificate cert) throws Exception {
        // Match Conscrypt NativeCrypto.X509_NAME_hash_old (MD5 of the DER subject).
        byte[] digest = MessageDigest.getInstance("MD5").digest(cert.getSubjectX500Principal().getEncoded());
        long value = 0;
        for (int i = 0; i < 4; i++) value |= (digest[i] & 255L) << (i * 8);
        return String.format(Locale.ROOT, "%08x", value);
    }

    private static String store(File dir, X509Certificate cert) throws Exception {
        String hash = hash(cert);
        byte[] der = cert.getEncoded();
        File available = null;
        for (int index = 0; ; index++) {
            File candidate = new File(dir, hash + "." + index);
            if (!candidate.exists()) {
                available = candidate;
                break;
            }
            if (Arrays.equals(der, parse(read(candidate), false).getEncoded())) return candidate.getName();
        }
        // Duplicates can occur beyond a removed slot; retain their existing filename.
        for (File candidate : certificates(dir)) {
            if (candidate.getName().startsWith(hash + ".") &&
                Arrays.equals(der, parse(read(candidate), false).getEncoded())) return candidate.getName();
        }
        String pem = "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der) +
            "\n-----END CERTIFICATE-----\n";
        write(available, pem.getBytes(StandardCharsets.US_ASCII));
        return available.getName();
    }

    private static void write(File target, byte[] data) throws Exception {
        File temp = File.createTempFile(".certificate-", ".tmp", target.getParentFile());
        try {
            try (FileOutputStream out = new FileOutputStream(temp)) {
                out.write(data);
                out.getFD().sync();
            }
            if (target.exists() || !temp.renameTo(target)) throw new IllegalArgumentException("Cannot create " + target);
        } finally {
            temp.delete();
        }
    }

    private static String fingerprint(X509Certificate cert) throws Exception {
        StringBuilder value = new StringBuilder();
        for (byte part : MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())) {
            if (value.length() > 0) value.append(':');
            value.append(String.format(Locale.ROOT, "%02X", part & 255));
        }
        return value.toString();
    }

    private static String quote(String value) {
        StringBuilder json = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') json.append('\\').append(c);
            else if (c < 32) json.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            else json.append(c);
        }
        return json.append('"').toString();
    }
}
