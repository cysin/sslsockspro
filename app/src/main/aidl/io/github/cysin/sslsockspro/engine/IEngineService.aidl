package io.github.cysin.sslsockspro.engine;
import io.github.cysin.sslsockspro.engine.IEngineCallback;
interface IEngineService {
    oneway void start(String profileId, String sessionId, String resolvedGateways, IEngineCallback callback);
    oneway void stop(String sessionId);
    boolean stopAndWait(String sessionId);
    /** The physical network changed; sameNetwork means only its addresses did. */
    oneway void networkChanged(String sessionId, boolean sameNetwork);
    /** Traffic reports; zero pauses them while no screen shows the counters. */
    oneway void setStatsInterval(String sessionId, long milliseconds);
    String versions();
}
