# CloudServer

This is a minimal Python HTTP server that accepts uploaded files and stores them in the `CloudData` folder.

Usage (PowerShell):

1. Start the server:

```powershell
python .\main.py --host 0.0.0.0 --port 8000
```

2. Upload a file using PowerShell (example):

```powershell
$filePath = 'C:\path\to\your\file.txt'
$form = @{ 'file' = Get-Item $filePath }
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/upload' -Method Post -Form $form
```

Or using curl:

```powershell
curl -F "file=@./test_file.txt" http://127.0.0.1:8000/upload
```

3. Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Files will be saved to the `CloudData` directory next to `main.py`.
