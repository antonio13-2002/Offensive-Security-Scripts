## 🐍 Python Environment & Libraries

This README serves as a reference for the local Python setup used to develop and run the exploit scripts across the `web` and `BIN` directories.

Below there is a compehensive list of the core Python libraries utilized to solve the Offensive Security challenges.

### 🛠 Core libraries & Tools

* **`pwntools`**: The fundamental CTF framework. Extensively used in the `BIN` challenges for interacting with binaries, crafting payloads, memory leaking, and managing local/remote processes.
* **`requests`**: The go-to package for making HTTP requests in Python, managing session cookies, and crafting specific payloads for the `web` challenges.
* **`ropper`**: Library to display information about binary files in different file formats and you to search gadgets to build rop chains for different architectures (x86/X86_64, ARM/ARM64, MIPS/MIPS64, PowerPC/PowerPC64, SPARC64). 
* **`pycryptodome`**: Utilized for cryptographic operations, manipulating hashes, and solving crypto-related puzzles embedded within the challenges.

### ⚙️ Local Setup Note
If you wish to replicate the environment and test the scripts locally, simply set up a standard Python virtual environment and install the required tools:

```bash
python3 -m venv venv
source venv/bin/activate
pip install pwntools requests ropper pycryptodome
