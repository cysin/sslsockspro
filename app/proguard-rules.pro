-keep class io.github.cysin.sslsockspro.engine.HevEngine { *; }
-keepclasseswithmembernames class * { native <methods>; }
# Credentials use Bouncy Castle's lightweight API only; no provider classes
# are loaded reflectively, so R8 may remove every unreferenced algorithm.
-dontwarn org.bouncycastle.**
-dontwarn org.slf4j.impl.**
-dontwarn lombok.Generated
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.MustBeClosed
