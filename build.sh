cd decoder
docker run --rm -v ./build_out:/out -v ./:/decoder -v ./../secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
cd ..
python3 -m ectf25.utils.flash ./decoder/build/max78000.bin /dev/tty.usbmodem*
