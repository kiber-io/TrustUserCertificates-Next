package io.kiber.tuc.probe;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Typeface;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.net.URL;
import java.io.File;
import java.io.FileOutputStream;
import javax.net.ssl.HttpsURLConnection;

public final class ProbeActivity extends Activity {
    private static native int[] inspect();
    private TextView status;
    private String report = "";

    @Override public void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        getWindow().getDecorView().setSystemUiVisibility(
            android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | android.view.View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (20 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        scroll.addView(content);
        setContentView(scroll);
        TextView title = new TextView(this);
        title.setText("TUC Hook Probe");
        title.setTextSize(26);
        content.addView(title);
        status = new TextView(this);
        status.setTextIsSelectable(true);
        status.setTypeface(Typeface.MONOSPACE);
        status.setTextSize(15);
        status.setPadding(0, padding, 0, padding);
        content.addView(status);
        Button refresh = new Button(this);
        refresh.setText("Refresh");
        refresh.setOnClickListener(view -> refresh());
        content.addView(refresh);
        Button copy = new Button(this);
        copy.setText("Copy report");
        copy.setOnClickListener(view -> ((ClipboardManager) getSystemService(CLIPBOARD_SERVICE))
            .setPrimaryClip(ClipData.newPlainText("TUC Hook Probe", report)));
        content.addView(copy);
        TextView hint = new TextView(this);
        hint.setText("Select TUC Hook Probe in the module WebUI, change hooks, save, then reopen this app.\n\nBaseline: CT required on Android 16+, system and user CA sources absent, embedded CA present.\n\nAn enabled source with 0 CAs means its store is empty. This reads the actual app config; it does not enable hooks itself.");
        hint.setPadding(0, padding, 0, padding);
        content.addView(hint);
        EditText address = new EditText(this);
        address.setSingleLine(true);
        address.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        address.setText("https://example.com");
        content.addView(address);
        TextView connection = new TextView(this);
        connection.setTextIsSelectable(true);
        Button connect = new Button(this);
        connect.setText("Test HTTPS");
        connect.setOnClickListener(view -> {
            final String target = address.getText().toString().trim();
            connect.setEnabled(false);
            connection.setText("Connecting…");
            new Thread(() -> {
                String outcome;
                HttpsURLConnection request = null;
                try {
                    URL url = new URL(target);
                    if (!"https".equalsIgnoreCase(url.getProtocol())) throw new IllegalArgumentException("Use an HTTPS URL");
                    request = (HttpsURLConnection) url.openConnection();
                    request.setConnectTimeout(10000);
                    request.setReadTimeout(10000);
                    request.setInstanceFollowRedirects(false);
                    outcome = "TLS accepted · HTTP " + request.getResponseCode();
                } catch (Exception error) {
                    StringBuilder text = new StringBuilder("Connection failed");
                    for (Throwable cause = error; cause != null; cause = cause.getCause())
                        text.append("\n").append(cause.getClass().getSimpleName()).append(": ").append(cause.getMessage());
                    outcome = text.toString();
                } finally { if (request != null) request.disconnect(); }
                final String text = outcome;
                runOnUiThread(() -> {
                    if (isDestroyed()) return;
                    connection.setText(text);
                    connect.setEnabled(true);
                });
            }, "tuc-https-probe").start();
        });
        content.addView(connect);
        content.addView(connection);
        refresh();
    }

    private static String source(int count) {
        return count < 0 ? "ABSENT" : "ENABLED (" + count + " CAs)";
    }

    private void refresh() {
        String prefix = "Package: " + getPackageName() + "\nAndroid: " + Build.VERSION.RELEASE
            + " (API " + Build.VERSION.SDK_INT + ")\nUID: " + android.os.Process.myUid() + "\n\n";
        try {
            System.loadLibrary("tuc-probe");
            int[] values = inspect();
            if (values == null || values.length != 4) throw new IllegalStateException("No config result");
            report = prefix + "CT: " + (values[0] < 0 ? "UNSUPPORTED" : values[0] == 0 ? "DISABLED" : "REQUIRED")
                + "\nSystem CAs: " + source(values[1]) + "\nUser CAs: " + source(values[2])
                + "\nEmbedded CAs: " + source(values[3]);
        } catch (Throwable error) {
            report = prefix + "Config inspection failed:\n" + android.util.Log.getStackTraceString(error);
        }
        status.setText(report);
        android.util.Log.i("TucHookProbe", report);
        try (FileOutputStream out = new FileOutputStream(new File(getFilesDir(), "report.txt"))) {
            out.write(report.getBytes("UTF-8"));
        } catch (java.io.IOException error) { android.util.Log.w("TucHookProbe", "Cannot save report", error); }
    }
}
