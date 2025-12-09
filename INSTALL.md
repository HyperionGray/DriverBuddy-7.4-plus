# ☠ DriverBuddy Installation Guide ☠

```
    ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝ 
    ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝  
    ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
                                                                                           
                        ☠ INSTALLATION INSTRUCTIONS ☠
```

This guide provides detailed installation instructions for DriverBuddy across all supported platforms.

## ☠ Prerequisites ☠

- **Python 3.6+** (Python 3.8+ recommended)
- At least one supported reverse engineering platform:
  - IDA Pro 7.x or 8.x
  - Ghidra 10.x+
  - Binary Ninja 3.x+
  - Radare2 5.x+

## ☠ Quick Installation ☠

### Method 1: Direct Download
```bash
# Clone or download the repository
git clone https://github.com/nccgroup/driverbuddy.git
cd driverbuddy
```

### Method 2: Python Package (if available)
```bash
pip install driverbuddy
```

## ☠ Platform-Specific Installation ☠

### IDA Pro Installation

#### Windows
```cmd
REM Copy to IDA plugins directory
copy /Y DriverBuddy.py "C:\Program Files\IDA Pro 8.0\plugins\"
xcopy /E /I DriverBuddy "C:\Program Files\IDA Pro 8.0\plugins\DriverBuddy"
```

#### Linux/macOS
```bash
# Copy to IDA plugins directory
cp DriverBuddy.py ~/.idapro/plugins/
cp -r DriverBuddy ~/.idapro/plugins/

# Alternative system-wide installation
sudo cp DriverBuddy.py /opt/ida/plugins/
sudo cp -r DriverBuddy /opt/ida/plugins/
```

#### Verification
1. Start IDA Pro
2. Load any binary
3. Go to `Edit → Plugins`
4. Look for "DriverBuddy" in the list
5. Test with `Ctrl+Alt+D`

### Ghidra Installation

#### Script Installation
```bash
# Copy to user scripts directory
cp scripts/ghidra_driverbuddy.py ~/ghidra_scripts/
cp -r DriverBuddy ~/ghidra_scripts/

# Alternative: Copy to Ghidra installation
cp scripts/ghidra_driverbuddy.py "$GHIDRA_INSTALL_DIR/Ghidra/Features/Python/ghidra_scripts/"
cp -r DriverBuddy "$GHIDRA_INSTALL_DIR/Ghidra/Features/Python/ghidra_scripts/"
```

#### Verification
1. Start Ghidra
2. Open any project and binary
3. Open Script Manager (`Window → Script Manager`)
4. Look for `ghidra_driverbuddy.py` in the script list
5. Run the script

### Binary Ninja Installation

#### Plugin Installation
```bash
# Copy to Binary Ninja plugins directory
cp scripts/binja_driverbuddy.py ~/.binaryninja/plugins/
cp -r DriverBuddy ~/.binaryninja/plugins/

# Windows alternative
copy scripts\binja_driverbuddy.py "%APPDATA%\Binary Ninja\plugins\"
xcopy /E /I DriverBuddy "%APPDATA%\Binary Ninja\plugins\DriverBuddy"
```

#### Verification
1. Start Binary Ninja
2. Load any binary
3. Check `Tools` menu for "DriverBuddy" submenu
4. Try running "Analyze Driver"

### Radare2 Installation

#### Script Setup
```bash
# Install r2pipe dependency
pip install r2pipe

# Copy script to accessible location
cp scripts/r2_driverbuddy.py /usr/local/bin/
chmod +x /usr/local/bin/r2_driverbuddy.py

# Copy DriverBuddy package
cp -r DriverBuddy /usr/local/lib/python3.x/site-packages/
```

#### Verification
```bash
# Test r2pipe connection
r2 -
[0x00000000]> #!pipe python3 -c "import r2pipe; print('r2pipe works')"

# Test DriverBuddy
r2 /bin/ls
[0x00000000]> #!pipe python3 /usr/local/bin/r2_driverbuddy.py
```

## ☠ Advanced Installation ☠

### Development Installation
```bash
# Clone repository
git clone https://github.com/nccgroup/driverbuddy.git
cd driverbuddy

# Install in development mode
pip install -e .

# Install development dependencies
pip install -e .[dev]
```

### Virtual Environment Setup
```bash
# Create virtual environment
python -m venv driverbuddy-env

# Activate (Linux/macOS)
source driverbuddy-env/bin/activate

# Activate (Windows)
driverbuddy-env\Scripts\activate

# Install DriverBuddy
pip install -e .
```

### Docker Installation (Advanced)
```dockerfile
# Dockerfile for DriverBuddy development
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    git \
    radare2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install r2pipe

COPY . /opt/driverbuddy
WORKDIR /opt/driverbuddy

RUN pip install -e .

CMD ["python", "-c", "from DriverBuddy import main; main()"]
```

## ☠ Configuration ☠

### Environment Variables
```bash
# Add DriverBuddy to Python path
export PYTHONPATH="/path/to/driverbuddy:$PYTHONPATH"

# Set platform preferences (optional)
export DRIVERBUDDY_PLATFORM="ida"  # ida, ghidra, binja, r2
```

### Platform-Specific Configuration

#### IDA Pro
Create `~/.idapro/cfg/python.cfg`:
```ini
[PYTHON]
DRIVERBUDDY_ENABLED = YES
DRIVERBUDDY_AUTO_ANALYSIS = YES
```

#### Ghidra
Add to `~/.ghidra/.ghidra_10.x/preferences`:
```properties
driverbuddy.auto_analysis=true
driverbuddy.verbose_logging=false
```

## ☠ Troubleshooting ☠

### Common Issues

#### Import Errors
```bash
# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify DriverBuddy installation
python -c "from DriverBuddy import DriverAnalyzer; print('OK')"
```

#### Platform Detection Issues
```python
# Test platform detection
from DriverBuddy import get_platform_adapter
try:
    adapter = get_platform_adapter()
    print(f"Detected: {adapter.get_platform_name()}")
except Exception as e:
    print(f"Error: {e}")
```

#### Permission Issues (Linux/macOS)
```bash
# Fix permissions
chmod +x scripts/*.py
chmod -R 755 DriverBuddy/

# Install with user permissions
pip install --user -e .
```

### Platform-Specific Issues

#### IDA Pro
- **Issue**: Plugin not loading
- **Solution**: Check IDA Python console for errors
- **Command**: `Alt+F7` to open Python console

#### Ghidra
- **Issue**: Script not found
- **Solution**: Refresh script manager or check script paths
- **Command**: `Window → Script Manager → Refresh`

#### Binary Ninja
- **Issue**: Plugin not appearing in menu
- **Solution**: Check Binary Ninja log for errors
- **Command**: `View → Show Log`

#### Radare2
- **Issue**: r2pipe connection fails
- **Solution**: Ensure r2 is running and accessible
- **Command**: Test with `r2 -c 'q' /bin/ls`

## ☠ Verification ☠

### Test Installation
```bash
# Run test script
python examples/example_usage.py

# Test specific platform
python -c "
from DriverBuddy import get_platform_adapter
adapter = get_platform_adapter()
print(f'Platform: {adapter.get_platform_name()}')
print(f'Version: {adapter.get_platform_version()}')
print('Installation successful!')
"
```

### Performance Test
```python
# Test analysis performance
import time
from DriverBuddy import DriverAnalyzer, get_platform_adapter

start_time = time.time()
platform = get_platform_adapter()
analyzer = DriverAnalyzer(platform)
# analyzer.analyze_driver()  # Uncomment with actual driver
end_time = time.time()

print(f"Platform initialization: {end_time - start_time:.2f}s")
```

## ☠ Uninstallation ☠

### Remove DriverBuddy
```bash
# Remove pip installation
pip uninstall driverbuddy

# Remove manual installations
rm -rf ~/.idapro/plugins/DriverBuddy*
rm -rf ~/ghidra_scripts/DriverBuddy*
rm -rf ~/.binaryninja/plugins/DriverBuddy*
```

### Clean Configuration
```bash
# Remove configuration files
rm -f ~/.idapro/cfg/python.cfg
rm -f ~/.ghidra/.ghidra_*/preferences
```

---

```
                                    ☠ ☠ ☠
                            Installation Complete!
                                    ☠ ☠ ☠
```