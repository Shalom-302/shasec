# SHASEC — Qt6 Desktop Console

Client desktop (Qt6 / C++) pour piloter l'API SHASEC. **Console à sidebar**, thème
sombre, accents bleu/jaune.

## Ce qu'il fait

Navigation à gauche : **Dashboard / Cibles / Scans / Rapports / Réglages**.

- **Réglages** : URL de l'API (défaut `https://shasec.kortexai.dev`) + register / login.
- **Dashboard** : cartes (nb scans, cibles, findings/preuves de la sélection) + scans récents.
- **Cibles** : table des cibles (`GET /targets/`).
- **Scans** : nouveau scan (`POST /scans/quick`), table des scans (`GET /scans/`),
  polling auto, détail en onglets *Findings* / *Preuves* au clic d'un scan.
- **Rapports** : `Générer` (stocke dans MinIO) **et** `Télécharger & ouvrir` —
  `GET /scans/{id}/report/download` streame le fichier via l'API (auth), l'écrit en
  local et l'ouvre. Pas besoin d'exposer MinIO.

## Prérequis

- **Qt 6.3+** (Widgets + Network ; **WebSockets optionnel** — progression live si présent, polling sinon)
- **CMake 3.16+** et un compilateur C++17 (MSVC, MinGW, ou GCC/Clang)

## Build

### Le plus simple — Qt Creator
Ouvre `qt-client/CMakeLists.txt` dans Qt Creator → configure le kit Qt6 → **Run**.

### En ligne de commande

```bash
cd qt-client
cmake -B build -S . -DCMAKE_PREFIX_PATH=/chemin/vers/Qt/6.x.x/<compilo>
cmake --build build --config Release
```

Exemples de `CMAKE_PREFIX_PATH` :
- Windows (MinGW) : `C:/Qt/6.8.0/mingw_64`
- Windows (MSVC)  : `C:/Qt/6.8.0/msvc2019_64`
- macOS           : `~/Qt/6.8.0/macos`
- Linux           : `~/Qt/6.8.0/gcc_64`

## Packaging (distribuable, double-clic)

### Windows → `.exe` portable
```bat
cmake --build build --config Release
windeployqt build\shasec-client.exe
```
`windeployqt` copie les DLL Qt à côté de l'exe. Zippe le dossier `build\` → exécutable
sur n'importe quel Windows (sans Qt installé).

### macOS → `.app`
Le même code produit un bundle `shasec-client.app` (CMake `MACOSX_BUNDLE`). Pour
embarquer les frameworks Qt :
```bash
cmake -B build -S . -DCMAKE_PREFIX_PATH=~/Qt/6.8.0/macos
cmake --build build
macdeployqt build/shasec-client.app          # bundle les frameworks
# (optionnel) macdeployqt build/shasec-client.app -dmg   # produit un .dmg
```
`shasec-client.app` est alors distribuable (glisser dans /Applications).

> Le plus simple sur les deux OS : ouvrir le `CMakeLists.txt` dans **Qt Creator** et
> faire *Build* en mode **Release**.

## Fichiers

| Fichier | Rôle |
|---|---|
| `main.cpp` | point d'entrée + thème dark (QSS) |
| `ApiClient.{h,cpp}` | couche REST (enveloppe `{code,msg,data}` + Bearer) |
| `MainWindow.{h,cpp}` | l'interface (connexion / scan / résultats / rapport) |

## Note

Client d'audit **autorisé** uniquement — il pilote SHASEC, qui n'attaque que des
cibles consenties (`is_authorized` + consentement par scan).
