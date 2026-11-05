# Shizuku binds TimerUserService by component name and talks over the
# generated AIDL stubs; R8 must keep both sides in release builds.
-keep class com.timerz9turbo.app.shizuku.TimerUserService { *; }
-keep interface com.timerz9turbo.app.shizuku.ITimerUserService { *; }
-keep interface com.timerz9turbo.app.shizuku.ITimerCallback { *; }
-keep class com.timerz9turbo.app.shizuku.ITimerUserService$Stub { *; }
-keep class com.timerz9turbo.app.shizuku.ITimerCallback$Stub { *; }
