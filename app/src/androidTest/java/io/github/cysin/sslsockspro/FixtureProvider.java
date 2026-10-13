package io.github.cysin.sslsockspro;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;

/** Test APK only. No Kotlin/application dependency: this provider also runs
 * in the test package's standalone process, outside the instrumentation loader. */
public final class FixtureProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (getContext().getPackageManager().checkSignatures(Binder.getCallingUid(), Process.myUid()) != PackageManager.SIGNATURE_MATCH)
            throw new SecurityException("Fixture access requires the test signing certificate");
        List<String> segments = uri.getPathSegments();
        if (!"r".equals(mode) || segments.size() != 1)
            throw new FileNotFoundException("Unsupported fixture request");
        String name = segments.get(0);
        if (!"device-client.zip".equals(name) && !"openvpn-fixture.zip".equals(name))
            throw new FileNotFoundException("Unknown fixture");
        return ParcelFileDescriptor.open(new File(getContext().getFilesDir(), name), ParcelFileDescriptor.MODE_READ_ONLY);
    }
    @Override public String getType(Uri uri) { return "application/zip"; }
    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] args, String sort) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) { return 0; }
    @Override public int delete(Uri uri, String selection, String[] args) { return 0; }
}
