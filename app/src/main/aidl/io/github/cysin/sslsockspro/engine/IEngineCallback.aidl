package io.github.cysin.sslsockspro.engine;
import android.os.ParcelFileDescriptor;
interface IEngineCallback {
    boolean protectSocket(in ParcelFileDescriptor socket, String sessionId);
    ParcelFileDescriptor acquireTun(String networkConfiguration, String sessionId);
    /** Codes are defined in EngineEvent; detail is diagnostic, not UI wording. */
    void event(int code, String detail, String sessionId);
    void traffic(long received, long sent, String sessionId);
}
