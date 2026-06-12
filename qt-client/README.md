# SHASEC — Qt6 Desktop Console

Client desktop (Qt6 / C++) pour piloter l'API SHASEC : connexion, lancement de
scans, consultation des findings + preuves d'exploitation, génération de rapport.
Thème « security console » dark.

## Ce qu'il fait

- **Connexion** : register / login (JWT stocké en mémoire).
- **Scan** : `POST /scans/quick` (URL, type, exploitation active, token cible optionnel).
- **Suivi** : polling auto du statut jusqu'à `completed`/`failed`.
- **Résultats** : onglets *Findings* et *Preuves d'exploitation* (tables).
- **Rapport** : `POST /scans/{id}/report?format=pdf|html|markdown|json&lang=fr`,
  bouton *Ouvrir* (navigateur).

L'URL par défaut pointe sur `https://shasec.kortexai.dev` — modifiable dans la barre du haut.

## Prérequis

- **Qt 6.3+** (Widgets + Network)
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
- Windows (MinGW) : `C:/Qt/6.7.2/mingw_64`
- Windows (MSVC)  : `C:/Qt/6.7.2/msvc2019_64`
- Linux           : `~/Qt/6.7.2/gcc_64`

Le binaire `shasec-client` est généré dans `build/`.

> Windows : si l'exe ne trouve pas les DLL Qt au lancement, exécute
> `windeployqt build/shasec-client.exe` (livré avec Qt) pour copier les DLL.

## Fichiers

| Fichier | Rôle |
|---|---|
| `main.cpp` | point d'entrée + thème dark (QSS) |
| `ApiClient.{h,cpp}` | couche REST (enveloppe `{code,msg,data}` + Bearer) |
| `MainWindow.{h,cpp}` | l'interface (connexion / scan / résultats / rapport) |

## Note

Client d'audit **autorisé** uniquement — il pilote SHASEC, qui n'attaque que des
cibles consenties (`is_authorized` + consentement par scan).
