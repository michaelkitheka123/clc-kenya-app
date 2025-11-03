[app]
# App title
title = CLC Kenya

# Package name (MUST BE UNIQUE - change if needed)
package.name = clckenya

# Package domain (reverse format)
package.domain = org.clckenya

# Source directory
source.dir = .

# Main entry point
source.main = main.py

# Include ALL your file types
source.include_exts = py,png,jpg,jpeg,kv,atlas,ttf,otf,json

# Requirements - CRITICAL SECTION!
requirements = 
    python3,
    kivy==2.3.0,
    openssl,
    requests,
    certifi,
    chardet,
    idna,
    urllib3

# Android API settings
android.api = 33
android.minapi = 21
android.sdk = 21
android.ndk = 25b

# Permissions
android.permissions = 
    INTERNET,
    ACCESS_NETWORK_STATE,
    WRITE_EXTERNAL_STORAGE,
    READ_EXTERNAL_STORAGE

# App version
version = 0.1

# Orientation
orientation = portrait

# Icons
icon.filename = assets/logo.png
presplash.filename = assets/logo.png

# Build type (debug for testing)
build_type = debug

# Accept SDK licenses automatically
android.accept_sdk_license = True

[buildozer]
# Log level (2 = verbose)
log_level = 2