#!/bin/bash
set -e

# ===== 參數設定 =====
APP_NAME="DeviceReboot"
MAIN_PY="devicereboot.py"
ICON_FILE="DeviceCheck.png"
DESKTOP_ENTRY="${APP_NAME}.desktop"
APPDIR="${APP_NAME}.AppDir"

echo "[1/8] 安裝系統依賴套件..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv wget build-essential python3-dev \
qtbase5-dev qt5-qmake libqt5widgets5 libqt5gui5 libqt5core5a libgl1-mesa-dev libxcb-xinerama0 patchelf

echo "[2/8] 清理舊檔，建立全新 venv..."
rm -rf venv dist build ${APP_NAME}.spec
python3 -m venv venv
source venv/bin/activate

echo "[3/8] venv pip 位置: $(which pip)"
pip install --upgrade pip setuptools wheel

echo "[4/8] 安裝所有必要依賴（都在 venv 內）..."
pip install pandas aiohttp psutil openpyxl xlrd matplotlib
pip install --only-binary :all: PyQt5
pip install pyinstaller

echo "[5/8] 用 pyinstaller 打包主程式 (全部在 venv)..."
pyinstaller --noconfirm --clean --onefile --name "$APP_NAME" --icon="$ICON_FILE" "$MAIN_PY"

cd dist

echo "[6/8] 下載 appimagetool（若已存在則跳過）..."
if [ ! -f appimagetool-x86_64.AppImage ]; then
    wget -O appimagetool-x86_64.AppImage https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x appimagetool-x86_64.AppImage
fi

echo "[7/8] 準備 AppDir 結構..."
rm -rf ${APPDIR}
mkdir -p ${APPDIR}/usr/bin
cp "$APP_NAME" ${APPDIR}/usr/bin/
cp ../$ICON_FILE ${APPDIR}/

# ==== 製作 AppRun 軟連結（AppImage 必備）====
ln -sf usr/bin/$APP_NAME ${APPDIR}/AppRun

cat > ${APPDIR}/${DESKTOP_ENTRY} <<EOF
[Desktop Entry]
Name=DeviceReboot
Comment=DeviceRebootTool
Exec=${APP_NAME}
Icon=DeviceCheck
Terminal=false
Type=Application
Categories=Utility;
EOF

echo "[8/8] 用 appimagetool 產生 AppImage..."
./appimagetool-x86_64.AppImage --no-appstream ${APPDIR}

deactivate

echo ""
echo "🎉 打包完成！AppImage 路徑：$(pwd)/${APP_NAME}-x86_64.AppImage"
echo "任何一台 Ubuntu 20.04 (或更新版) 直接執行即可。"

