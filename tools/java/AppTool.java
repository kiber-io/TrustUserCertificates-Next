import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.os.UserHandle;
import android.os.UserManager;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;

/** Installed app labels and icons, resolved by Android rather than APK filename guesses. */
public final class AppTool {
    public static void main(String[] args) {
        try {
            if (args.length != 2 || !args[0].equals("apps")) {
                throw new IllegalArgumentException("Usage: apps ICON_DIRECTORY");
            }
            File icons = new File(args[1]);
            if ((!icons.isDirectory() && !icons.mkdirs()) || !icons.setReadable(true, false) ||
                !icons.setExecutable(true, false)) throw new IOException("Cannot prepare icon directory");
            Looper.prepareMainLooper();
            Class<?> activityThread = Class.forName("android.app.ActivityThread");
            Object thread = activityThread.getMethod("systemMain").invoke(null);
            Context context = (Context) activityThread.getMethod("getSystemContext").invoke(thread);
            JSONArray apps = new JSONArray();
            UserManager users = context.getSystemService(UserManager.class);
            List<?> profiles = (List<?>) UserManager.class.getMethod("getUsers").invoke(users);
            for (Object profile : profiles) {
                Class<?> info = profile.getClass();
                int userId = info.getField("id").getInt(profile);
                String userName = (String) info.getField("name").get(profile);
                boolean managed = (Boolean) info.getMethod("isManagedProfile").invoke(profile);
                if (userId < 0 || userId > Integer.MAX_VALUE / 100000) {
                    throw new IllegalArgumentException("Invalid Android user ID");
                }
                Context userContext = (Context) Context.class.getMethod("createContextAsUser", UserHandle.class, int.class)
                    .invoke(context, UserHandle.getUserHandleForUid(userId * 100000), 0);
                PackageManager manager = userContext.getPackageManager();
                for (ApplicationInfo app : manager.getInstalledApplications(0)) {
                    int appId = app.uid % 100000;
                    if (app.uid / 100000 != userId || appId < 10000 || appId >= 20000) continue;
                    String label = app.packageName;
                    String icon = null;
                    try {
                        label = manager.getApplicationLabel(app).toString();
                    } catch (RuntimeException e) {
                        System.err.println("AppTool: label " + app.packageName + ": " + e);
                    }
                    try {
                        // OEM live icons can depend on a fully bound app's font initialization.
                        icon = icon(app.icon == 0 ? manager.getDefaultActivityIcon() :
                            manager.getResourcesForApplication(app).getDrawable(app.icon, null), icons, app);
                    } catch (PackageManager.NameNotFoundException | IOException | RuntimeException e) {
                        System.err.println("AppTool: icon " + app.packageName + ": " + e);
                    }
                    apps.put(new JSONObject().put("package", app.packageName).put("uid", app.uid)
                        .put("userId", userId).put("userName", userName == null ? "User " + userId : userName)
                        .put("profile", managed ? "work" : userId == 0 ? "personal" : "user")
                        .put("label", label).put("icon", icon == null ? JSONObject.NULL : icon));
                }
            }
            System.out.println(apps);
        } catch (Exception e) {
            System.err.println("AppTool: " + e);
            System.exit(1);
        }
    }

    private static String icon(Drawable drawable, File directory, ApplicationInfo app) throws IOException {
        if (!app.packageName.matches("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+")) {
            throw new IllegalArgumentException("Invalid package name");
        }
        String name = app.uid + "-" + app.packageName + ".png";
        Bitmap bitmap = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888);
        File temp = null;
        try {
            drawable.setBounds(0, 0, 48, 48);
            drawable.draw(new Canvas(bitmap));
            temp = File.createTempFile(".icon-", ".tmp", directory);
            try (FileOutputStream png = new FileOutputStream(temp)) {
                if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, png)) {
                    throw new IOException("Cannot encode icon");
                }
            }
            if (!temp.setReadable(true, false) || !temp.renameTo(new File(directory, name))) {
                throw new IOException("Cannot publish icon");
            }
            return "app-icons/" + name;
        } finally {
            bitmap.recycle();
            if (temp != null) temp.delete();
        }
    }
}
