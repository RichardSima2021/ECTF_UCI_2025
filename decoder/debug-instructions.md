# Windows
> Note: This guide assumes you have MaximSDK installed in your root directory (in C:\MaximSDK)
## Downloading and Extracting files
Download the this [zipfile](https://drive.google.com/file/d/1F1EyeFTf4KM0dSA1VSZTTa3ObT6eANWy/view?usp=sharing)

Go to the root directory of the project
Make a folder called `.vscode` if you don't have one already
Clear the contents and extract the contents of the zip file into it

## Editing global settings
You're going to have to edit some of your global VSCode user settings
Press `ctrl-shift-p` to open up the command prompt
Enter `Preferences: Open User Settings (JSON)`
Enter:
```
{
    "MAXIM_PATH": "C:/MaximSDK",
    "ECTF_PATH": "C:/Users/min/eCTF/2025-ectf-insecure-example"
}
```
Copy and paste the above if you have nothing in your settings. If there are already things, just copy and paste the inner contents of the bracket and add it within the brackets of the settings anywhere.
> Note: If you set MAXIM_PATH before, make sure to switch the backslashes to forward slashes (\ -> /) If you don't, things will break

## Turning on Debug Mode
Go into the decoder directory
Open Dockerfile in a text editor
In line 38, change line
```
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
```
to
```
ENTRYPOINT ["bash", "-c", "make DEBUG=1 PROJ_CFLAGS+='-g' DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
```

## Building the debug binary
Remove the build folder in the decoder directory
Run
```
rmdir .\build
```
Or just remove it in file explorer
Activate the python virtual environment if you haven't already
```
cd ..
.\.venv\Scripts\Activate.ps1
```
Then build the binary
```
docker run --rm -v .\build_out:/out -v .\:/decoder -v .\..\secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
```

## Flash the debug binary
Plug in the MAX78000 FTHR Board while holding SW1 (bottom right button if you're holding the usb port on top)

Use the ectf tool to flash the binary (Example below)
```
python -m ectf25.utils.flash .\build\max78000.bin COM3
```
Check device manager under ports to see what port your board is connected to

## Try debugging
Open VS Code in the project directory, and open up the debug window (`ctrl-shift-d`)

Press eCTF on top.
Hope it works...




# Linux
> Note: This guide assumes you have MaximSDK installed in your home directory (in /home/username/MaximSDK)
## Downloading and Extracting files
Download the this [zipfile](https://drive.google.com/file/d/1F1EyeFTf4KM0dSA1VSZTTa3ObT6eANWy/view?usp=sharing)

Go to the root directory of the project
Make a folder called `.vscode` if you don't have one already
Clear the contents and extract the contents of the zip file into it

## Editing global settings
You're going to have to edit some of your global VSCode user settings
Press `ctrl-shift-p` to open up the command prompt
Enter `Preferences: Open User Settings (JSON)`
Enter:
```
{
    "MAXIM_PATH": "/home/username/MaximSDK",
    "ECTF_PATH": "/home/username/eCTF/2025-ectf-insecure-example"
}
```
Copy and paste the above if you have nothing in your settings. If there are already things, just copy and paste the inner contents of the bracket and add it within the brackets of the settings anywhere.
> Note: You can't use ~ for your home directory, you must type it all in

## Turning on Debug Mode
Go into the decoder directory
Open Dockerfile in a text editor
In line 38, change line
```
ENTRYPOINT ["bash", "-c", "make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
```
to
```
ENTRYPOINT ["bash", "-c", "make DEBUG=1 PROJ_CFLAGS+='-g' DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]
```

## Building the debug binary
Remove the build folder in the decoder directory
Run
```
rm -rf build
```
Or just remove it in file explorer
Activate the python virtual environment if you haven't already
```
cd ..
source .venv/bin/activate
```
Then build the binary
```
docker run --rm -v ./build_out:/out -v ./:/decoder -v ./../secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
```

## Flash the debug binary
Plug in the MAX78000 FTHR Board while holding SW1 (bottom right button if you're holding the usb port on top)

Use the ectf tool to flash the binary (Example below)
```
python -m ectf25.utils.flash ./build/max78000.bin /dev/tty.usbmodem...
```
Check /dev to see what port your board is connected to

## Try debugging
Open VS Code in the project directory, and open up the debug window (`ctrl-shift-d`)

Press eCTF on top.
Hope it works...