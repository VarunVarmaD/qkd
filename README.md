# BB84 QKD Demonstration Simulator (Hackathon-Ready)

This is a **self-contained BB84 Quantum Key Distribution simulator** designed for hackathons and teaching demos.
It implements **Alice–Bob key generation**, **basis sifting**, **QBER estimation**, **eavesdropping (intercept–resend)**,
and a simple **one-time-pad** demo using the generated key.

## Features
- Configure number of qubits, channel noise, and whether **Eve** (eavesdropper) is present
- Basis sifting and **QBER** (quantum bit error rate) computation
- **Eavesdropping detection** using a public sample & threshold
- Derive a final key and use it in a **one-time pad** to encrypt/decrypt a sample message
- Streamlit UI for an interactive demo, plus a Python API

## Quickstart

```bash
# (Recommended) create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install deps
pip install -r requirements.txt

# Run the UI
streamlit run app.py
```

Open the local URL Streamlit prints (typically http://localhost:8501).

## Files
- `bb84.py` – pure-Python simulation engine
- `app.py` – Streamlit UI front-end
- `simulate.py` – CLI runner (no UI)
- `requirements.txt` – minimal dependencies

## Notes
- This is a *classical simulation* of the BB84 protocol that captures key ideas (random bases, sifting, QBER, Eve).
- For a hardware/quantum-circuit demo, consider adding an optional Qiskit visualization step (not required here).

## Suggested Demo Flow (for judges)
1. Set **Eve OFF**, noise low → show low QBER and successful key generation.
2. Toggle **Eve ON** → show **QBER jump ~25%** and **abort** (key discarded).
3. Use the established key to **encrypt/decrypt** a short message using one-time pad.
