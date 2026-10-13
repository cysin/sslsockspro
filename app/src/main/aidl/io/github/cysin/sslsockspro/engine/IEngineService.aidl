package io.github.cysin.sslsockspro.engine;
import io.github.cysin.sslsockspro.engine.IEngineCallback;
interface IEngineService {
    oneway void start(String profileId, String sessionId, String resolvedGateways, IEngineCallback callback);
    oneway void stop(String sessionId);
    String versions();
}
