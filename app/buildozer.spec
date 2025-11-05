[app]
title = CLC Kenya
package.name = clckenya
package.domain = org.clckenya

# Path setup
source.dir = .
source.main = main.py

# Include important files
source.include_exts = py,png,jpg,jpeg,kv,atlas,ttf,otf,json,db

# App requirements
requirements = python3,kivy==2.3.0,openssl,requests,certifi,chardet,idna,urllib3

# Android settings
android.api = 33
android.minapi = 21
android.ndk = 25b

# Important for CI builds — prevents some interactive prompts
android.accept_sdk_license = True
android.accept_ndk_license = True

# Permissions your app needs
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# App details
version = 0.1
orientation = portrait

# Branding
icon.filename = assets/logo.png
presplash.filename = assets/logo.png

# Debug build type
build_type = debug

# Disable logcat spam
log_level = 2

# Automatically download build tools
android.sdk_path = ~/.buildozer/android/platform/android-sdk
android.ndk_path = ~/.buildozer/android/platform/android-ndk-r25b

# Reduce CI crashes
p4a.branch = master

[buildozer]
warn_on_root = 0
log_level = 2
