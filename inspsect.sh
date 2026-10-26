objdump -t libmod_helloWorld.dylib               
strings libmod_helloWorld.dylib | grep -E "hello|true|vault|dv"

# https://abacktools.com/tools/deobfuscator/binary/macho-analyzer
codesign -d --entitlements - libmod_helloWorld.dylib 
objdump -d dateiname.dylib