# LLM-SOC
# Signature Deception in Sub-10B LLMs for SOC Automation

This repository contains the code, data, and statistical analysis for the paper:

> **"Signature Deception: How Sub-10B Language Models Fail as Autonomous Anomaly Detectors in SOC Environments"**

## Overview

We evaluate three sub-10B LLMs (Mistral-7B, Llama 3.2 (3B), Lily-Cybersecurity) on two datasets (live Suricata alerts and CIC-IDS2017 benchmark) across 12 experimental conditions.

**Key Finding:** Under misleading signatures, all models collapse to the benign base rate (17.5% on EVE, 7.0% on CSV), demonstrating a complete failure of discriminative classification — a phenomenon we term **Signature Deception**.

## Repository Structure

## Branches

| Branch | Contents |
|---|---|
| `Statistics` | Statistical analysis (paired t-tests, ANOVA, Cohen's d) |
| `code-for-LLM-analysis` | LLM inference code and prompts |
| `collecting-combined-sample` | Data engineering (combine.py, newsam.py, read-eve.py) |
| `soniayn-socllm-200r-sample` | The 200-record sample datasets (EVE + CSV) |

 ## Environment

### Hardware
- Host: Windows with VMware Workstation (v16.2.3)
- VM1 (Kali Linux v2025.2): Attack generation + Suricata IDS
- VM2 (Metasploitable 2): Vulnerable target

### Software Stack

| Component | Version | Purpose |
|---|---|---|
| VMware Workstation | 16.2.3 | Hypervisor |
| Kali Linux | 2025.2 | Attack platform |
| Metasploitable 2 | — | Vulnerable target |
| Suricata | 8.0.6-1 | IDS/IPS (inline mode) |
| Ollama | latest | Local LLM runtime |
| Python | 3.10+ | Analysis scripts |

### Models (via Ollama)

| Model | Parameters | VRAM |
|---|---|---|
| Mistral-7B | 7B | ~4.4 GB |
| Llama 3.2 | 3B | ~2.0 GB |
| Lily-Cybersecurity-7B-v0.2 | ~7B | ~4.4 GB |

### Datasets

- **EVE:** 200 records generated in air-gapped cyber range (see `soniayn-socllm-200r-sample/`)
- **CSV:** 200 records sampled from CIC-IDS2017 benchmark
