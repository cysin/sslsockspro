package io.github.cysin.sslsockspro.engine;
import android.os.ParcelFileDescriptor;
interface IEngineCallback {
    boolean protectSocket(in ParcelFileDescriptor socket, String sessionId);
    ParcelFileDescriptor acquireTun(String networkConfiguration, String sessionId);
    void status(String stage, String message, String sessionId);
    void traffic(long received, long sent, String sessionId);
}
