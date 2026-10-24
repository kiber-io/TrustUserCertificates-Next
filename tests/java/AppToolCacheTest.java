import android.content.pm.ApplicationInfo;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.util.Properties;

/** Run on Android against the installed AppTool, not SDK stub implementations. */
public final class AppToolCacheTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        Class<?> tool = Class.forName("AppTool");
        Method key = tool.getDeclaredMethod("iconKey", ApplicationInfo.class, String.class);
        Method name = tool.getDeclaredMethod("iconName", ApplicationInfo.class);
        Method publish = tool.getDeclaredMethod("writeCache", File.class, Properties.class);
        key.setAccessible(true); name.setAccessible(true); publish.setAccessible(true);
        File directory = new File(args[0]);
        File apk = new File(directory, "base.apk");
        Files.write(apk.toPath(), new byte[]{1});
        ApplicationInfo app = new ApplicationInfo();
        app.packageName = "io.kiber.tuc.probe"; app.uid = 12345; app.icon = 7; app.sourceDir = apk.getPath();
        Object original = key.invoke(null, app, "config-a");
        check(original.equals(key.invoke(null, app, "config-a")), "Unchanged inputs must reuse the cache");
        check(!original.equals(key.invoke(null, app, "config-b")), "Configuration changes must refresh icons");
        Files.write(apk.toPath(), new byte[]{1, 2});
        check(!original.equals(key.invoke(null, app, "config-a")), "APK content metadata changes must refresh icons");
        original = key.invoke(null, app, "config-a");
        check(apk.setLastModified(apk.lastModified() - 2000), "Cannot update fixture timestamp");
        check(!original.equals(key.invoke(null, app, "config-a")), "Same-size APK timestamp changes must refresh icons");
        original = key.invoke(null, app, "config-a");
        File replacement = new File(directory, "replacement.apk");
        Files.write(replacement.toPath(), Files.readAllBytes(apk.toPath()));
        check(replacement.setLastModified(apk.lastModified()), "Cannot preserve fixture timestamp");
        app.sourceDir = replacement.getPath();
        check(!original.equals(key.invoke(null, app, "config-a")), "Changed APK paths must refresh even with identical metadata");
        original = key.invoke(null, app, "config-a");
        app.icon = 8;
        check(!original.equals(key.invoke(null, app, "config-a")), "Drawable resource changes must refresh icons");
        File split = new File(directory, "split.apk");
        Files.write(split.toPath(), new byte[]{1});
        app.splitSourceDirs = new String[]{split.getPath()};
        original = key.invoke(null, app, "config-a");
        Files.write(split.toPath(), new byte[]{1, 2});
        check(!original.equals(key.invoke(null, app, "config-a")), "Split changes must refresh icons");
        java.lang.reflect.Field overlays = ApplicationInfo.class.getField("resourceDirs");
        overlays.set(app, new String[]{split.getPath()});
        original = key.invoke(null, app, "config-a");
        overlays.set(app, new String[]{apk.getPath()});
        check(!original.equals(key.invoke(null, app, "config-a")), "Overlay changes must refresh icons");
        Object personal = name.invoke(null, app);
        app.uid += 1100000;
        check(!personal.equals(name.invoke(null, app)), "Profiles must not share icon paths");
        app.packageName = "../escape";
        try { name.invoke(null, app); throw new AssertionError("Unsafe package was accepted"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof IllegalArgumentException, "Unexpected rejection"); }
        Properties values = new Properties();
        File target = new File(directory, "cache.properties");
        values.setProperty("icon", "first"); publish.invoke(null, target, values);
        values.setProperty("icon", "second"); publish.invoke(null, target, values);
        Properties read = new Properties();
        try (FileInputStream input = new FileInputStream(target)) { read.load(input); }
        check(read.equals(values), "Publishing must replace the complete cache");
        System.out.println("PASS: APK/split/overlay/config invalidation, profile paths and atomic cache replacement");
        System.exit(0);
    }
}
