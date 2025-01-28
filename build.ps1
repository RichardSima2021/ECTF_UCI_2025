# setup virtual environment

function Install-Bootloader {
    # Get the drive letter of the removable (DAPLink) drive
    $daplinkDrive = (Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }).DeviceID

    # Define the URL of the file you want to download
    $url = "https://rules.ectf.mitre.org/_downloads/6176d2473ff417b11a757dd7967b19c2/insecure.bin"

    # Define the local file path for downloading
    $localFilePath = ".\insecure.bin"

    # Define the destination path on the DAPLink drive
    $destinationPath = "$daplinkDrive\insecure.bin"

    # Create the temporary folder if it doesn't exist
    if (-not (Test-Path -Path $localFilePath)) {
        # Download the file to the local temporary folder
        Invoke-WebRequest -Uri $url -OutFile $localFilePath
    }

    

    # Move the file from the local folder to the DAPLink drive
    Copy-Item -Path $localFilePath -Destination $destinationPath

    # Optionally, confirm the file has been moved
    Write-Output "File has been moved to: $destinationPath"

}



function Use-Venv{
    if (-not( Test-Path -Path ".venv")) {
        python -m venv .venv --prompt ectf-example
    
        #Enable virtual environment 
        . .\.venv\Scripts\Activate.ps1
    
        #Install the host tools
        python -m pip install .\tools\
    
        #Install the host design design elements as an editable module 
        python -m pip install -e .\design\
    } else {
        . .\.venv\Scripts\Activate.ps1
    }
}

function Install-Secrets {
    # #check if secrets dir exists, if not, set it up.
    if (-not( Test-Path -Path "secrets")) {
        # secrets directory does not exist, so you need to run the generate secrets script.
        mkdir secrets
        python -m ectf25_design.gen_secrets secrets/secrets.json 1 3 4
    }
}

function Install-Decoder {
    Set-Location decoder 

    $output = docker image ls

    if (-not ($output -match "decoder")) {
        #Image does not exist
        docker build -t decoder .
    }

    docker run --rm -v .\build_out:/out -v .\:/decoder -v .\..\secrets:/secrets -e DECODER_ID=0xdeadbeef decoder

    Set-Location .. #return to root
}
function Flash-Decoder {
    $device_id = (Get-CimInstance Win32_SerialPort | Select-Object -ExpandProperty DeviceID)

    Write-Host "device found: " $device_id

    python -m ectf25.utils.flash .\decoder\build_out\max78000.bin $device_id
}

Install-Bootloader
Use-Venv
Install-Secrets
Install-Decoder
Flash-Decoder
