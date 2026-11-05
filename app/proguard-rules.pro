# Shizuku binds GhostlockUserService by component name and talks over the
# generated AIDL stubs; R8 must keep both sides in release builds.
-keep class com.timerz9turbo.app.shizuku.GhostlockUserService { *; }
-keep interface com.timerz9turbo.app.shizuku.IGhostlockUserService { *; }
-keep interface com.timerz9turbo.app.shizuku.IGhostlockCallback { *; }
-keep class com.timerz9turbo.app.shizuku.IGhostlockUserService$Stub { *; }
-keep class com.timerz9turbo.app.shizuku.IGhostlockCallback$Stub { *; }
