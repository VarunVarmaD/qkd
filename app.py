\
import streamlit as st
import numpy as np
from bb84 import run_bb84, bits_to_str, otp_encrypt, otp_decrypt

st.set_page_config(page_title="BB84 QKD Simulator", page_icon="🔒", layout="wide")

st.title("🔒 BB84 QKD Demonstration Simulator")
st.write("Configure the parameters, run the protocol, and see whether a secure key can be established.")

with st.sidebar:
    st.header("Parameters")
    n_qubits = st.slider("Number of qubits sent", 50, 5000, 1000, step=50)
    noise = st.slider("Channel noise (bit-flip prob.)", 0.0, 0.2, 0.02, step=0.01)
    eve_present = st.toggle("Eavesdropper (Eve) present?", value=False)
    sample_rate = st.slider("Public sample fraction", 0.0, 0.5, 0.2, step=0.05)
    threshold = st.slider("Abort threshold (QBER)", 0.01, 0.3, 0.11, step=0.01)
    seed = st.number_input("Seed (reproducible)", min_value=0, value=42)
    run = st.button("Run BB84")

if run:
    res = run_bb84(
        n_qubits=n_qubits,
        noise=noise,
        eve_present=eve_present,
        sample_rate=sample_rate,
        threshold=threshold,
        seed=int(seed),
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Raw bits (sent)", res.n_qubits)
        st.metric("Sifted bits (kept)", int(res.sifted_alice.size))
    with col2:
        st.metric("QBER (full sifted)", f"{100*res.qber_full:.2f}%")
        st.metric("QBER (public sample)", f"{100*res.qber_sample:.2f}%")
    with col3:
        if res.aborted:
            st.error("Key Aborted")
            st.write(res.reason)
            st.metric("Final key length", 0)
        else:
            st.success("Key Established ✅")
            st.metric("Final key length", int(res.final_key.size))

    with st.expander("Show raw & sifted data (truncated)"):
        st.code(f"Alice bases (0=Z,1=X): {bits_to_str(res.alice_bases, 256)}")
        st.code(f"Alice bits:           {bits_to_str(res.alice_bits, 256)}")
        st.code(f"Bob bases:            {bits_to_str(res.bob_bases, 256)}")
        st.code(f"Bob bits:             {bits_to_str(res.bob_bits, 256)}")
        st.code(f"Sift mask:            {bits_to_str(res.sift_mask.astype(int), 256)}")
        st.code(f"Sifted Alice:         {bits_to_str(res.sifted_alice, 256)}")
        st.code(f"Sifted Bob:           {bits_to_str(res.sifted_bob, 256)}")
        if res.eve_present and res.eve_bases is not None:
            st.code(f"Eve bases:            {bits_to_str(res.eve_bases, 256)}")

    st.divider()
    st.header("One-Time Pad Demo")
    pt = st.text_input("Message to encrypt", "hello quantum world")
    if st.button("Encrypt & Decrypt with Current Key", disabled=res.aborted or res.final_key.size == 0):
        _, ct = otp_encrypt(pt, res.final_key)
        dec = otp_decrypt(ct, res.final_key)
        st.write("Ciphertext (hex):")
        st.code(ct.hex())
        st.write("Decrypted plaintext:")
        st.code(dec)

else:
    st.info("Configure parameters in the sidebar and click **Run BB84**.")
