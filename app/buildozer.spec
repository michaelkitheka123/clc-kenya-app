[app]
title = CLC Kenya
package.name = clckenya
package.domain = org.clckenya

# ---------------------------------------------------
# Paths
# ---------------------------------------------------
source.dir = .
source.main = main.py
source.include_exts = py,png,jpg,jpeg,kv,atlas,ttf,otf,json,db

# ---------------------------------------------------
# App Requirements
# ---------------------------------------------------
# Core + Networking + AppWrite SDK + Email + SQLite
requirements = python3,kivy==2.3.0,openssl,requests,urllib3,certifi,chardet,idna,smtplib,sqlite3,appwrite

# ---------------------------------------------------
# Android Settings
# ---------------------------------------------------
android.api = 33
android.minapi = 21
android.ndk = 25b
android.accept_sdk_license = True
android.accept_ndk_license = True
orientation = portrait

# ---------------------------------------------------
# Permissions
# ---------------------------------------------------
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

# ---------------------------------------------------
# App Identity & Branding
# ---------------------------------------------------
version = 0.1
icon.filename = assets/logo.png
presplash.filename = assets/presplash.png
presplash.keep_ratio = False        # 🔥 makes it fill the entire screen
presplash.scale = 1.0
presplash.background_color = #0b1524
fullscreen = 1                      # Ensures black bars are removed

# ---------------------------------------------------
# Logging & Debug
# ---------------------------------------------------
build_type = debug
log_level = 2

# ---------------------------------------------------
# Paths (auto-managed by Buildozer)
# ---------------------------------------------------
android.sdk_path = ~/.buildozer/android/platform/android-sdk
android.ndk_path = ~/.buildozer/android/platform/android-ndk-r25b

# ---------------------------------------------------
# Optimizations
# ---------------------------------------------------
android.strip_debug = True
android.requirements_all = False

# Ensure OpenSSL libraries link correctly on ARM
android.add_libs_armeabi_v7a = libcrypto1.1.so,libssl1.1.so
android.add_libs_arm64_v8a = libcrypto1.1.so,libssl1.1.so

# ---------------------------------------------------
# Fixes & Stability
# ---------------------------------------------------
p4a.branch = master

[buildozer]
warn_on_root = 0
log_level = 2
