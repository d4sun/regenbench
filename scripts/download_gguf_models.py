#!/usr/bin/env python3
"""Download benign GGUF models per task cluster into data/crawled/<cluster>/.

Targets 25 GGUF files per cluster across 5 task clusters (125 total).
Size varies per cluster: text-classification and feature-extraction are
small (5–19 MB); token-classification and question-answering use larger
NER/PII/encoder models (up to ~950 MB) since the Hub has fewer small GGUFs
for those tasks.

Each download shows a tqdm progress bar. Files already present are skipped.

Usage:
    python3 scripts/download_gguf_models.py [--out-dir data/crawled] [--cluster qa,token]
    python3 scripts/download_gguf_models.py --list  # just print the manifest
    python3 scripts/download_gguf_models.py --stats  # per-cluster counts
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from huggingface_hub import hf_hub_download
from tqdm import tqdm

# (repo_id, filename, cluster, display_name)
# Verified via HfApi model_info(files_metadata=True) at authoring time.
# Sizes are approximate; tqdm shows the exact live size.
GGUF_MODELS: list[tuple[str, str, str, str]] = [
    # ───────────────────────────────────────────────────────────────────────
    # text-generation  (3 existing + 22 new = 25)
    # Existing (already on disk):
    ("ggml-org/models", "tinyllamas/stories260K.gguf", "text-generation", "ggml-org_stories260K"),
    ("ggml-org/models", "tinyllamas/stories15M-q4_0.gguf", "text-generation", "ggml-org_stories15M-q4_0"),
    ("ggml-org/models", "tinyllamas/stories15M-q8_0.gguf", "text-generation", "ggml-org_stories15M-q8_0"),
    # New (smallest first, relaxed to ~630 MB):
    ("LiquidAI/LFM2.5-230M-GGUF", "LFM2.5-230M-Q4_0.gguf", "text-generation", "LiquidAI_LFM2.5-230M"),
    ("unsloth/functiongemma-270m-it-GGUF", "functiongemma-270m-it-UD-IQ2_XXS.gguf", "text-generation", "unsloth_functiongemma-270m"),
    ("unsloth/gemma-3-270m-it-GGUF", "gemma-3-270m-it-UD-IQ2_XXS.gguf", "text-generation", "unsloth_gemma-3-270m"),
    ("LiquidAI/LFM2.5-2.6B-DSpark-GGUF", "LFM2.5-2.6B-DSpark-Q4_K_M.gguf", "text-generation", "LiquidAI_LFM2.5-2.6B-DSpark"),
    ("unsloth/Qwen3-0.6B-GGUF", "Qwen3-0.6B-UD-IQ1_S.gguf", "text-generation", "unsloth_Qwen3-0.6B"),
    ("LiquidAI/LFM2-350M-GGUF", "LFM2-350M-Q4_0.gguf", "text-generation", "LiquidAI_LFM2-350M"),
    ("LiquidAI/LFM2.5-350M-GGUF", "LFM2.5-350M-Q4_0.gguf", "text-generation", "LiquidAI_LFM2.5-350M"),
    ("prism-ml/Bonsai-1.7B-gguf", "Bonsai-1.7B-Q1_0.gguf", "text-generation", "prism-ml_Bonsai-1.7B"),
    ("Qwen/Qwen2-0.5B-Instruct-GGUF", "qwen2-0_5b-instruct-q2_k.gguf", "text-generation", "Qwen_Qwen2-0.5B"),
    ("Jackrong/Qwen3.5-0.8B-Claude-4.6-Opus-Reasoning-Distilled-GGUF", "Qwen3.5-0.8B.Q2_K.gguf", "text-generation", "Jackrong_Qwen3.5-0.8B-Distilled"),
    ("Qwen/Qwen2.5-0.5B-Instruct-GGUF", "qwen2.5-0.5b-instruct-q2_k.gguf", "text-generation", "Qwen_Qwen2.5-0.5B"),
    ("unsloth/Llama-3.2-1B-Instruct-GGUF", "Llama-3.2-1B-Instruct-UD-IQ1_S.gguf", "text-generation", "unsloth_Llama-3.2-1B"),
    ("LiquidAI/LFM2-700M-GGUF", "LFM2-700M-Q4_0.gguf", "text-generation", "LiquidAI_LFM2-700M"),
    ("tiiuae/Falcon-H1R-7B-GGUF", "Falcon-H1R-7B-IQ2_M.gguf", "text-generation", "tiiuae_Falcon-H1R-7B"),
    ("prism-ml/Ternary-Bonsai-1.7B-gguf", "Ternary-Bonsai-1.7B-PQ2_0.gguf", "text-generation", "prism-ml_Ternary-Bonsai-1.7B"),
    ("unsloth/LFM2.5-1.2B-Instruct-GGUF", "LFM2.5-1.2B-Instruct-Q2_K.gguf", "text-generation", "unsloth_LFM2.5-1.2B"),
    ("unsloth/Qwen3-1.7B-GGUF", "Qwen3-1.7B-UD-IQ1_S.gguf", "text-generation", "unsloth_Qwen3-1.7B"),
    ("unsloth/gemma-3-1b-it-GGUF", "gemma-3-1b-it-UD-IQ1_S.gguf", "text-generation", "unsloth_gemma-3-1B"),
    ("DavidAU/L3-Dark-Planet-8B-GGUF", "L3-Dark-Planet-8B-D_AU-Q6_k.gguf", "text-generation", "DavidAU_L3-Dark-Planet-8B"),
    ("prism-ml/Bonsai-4B-gguf", "Bonsai-4B-Q1_0.gguf", "text-generation", "prism-ml_Bonsai-4B"),
    ("Qwen/Qwen3-0.6B-GGUF", "Qwen3-0.6B-Q8_0.gguf", "text-generation", "Qwen_Qwen3-0.6B-Q8_0"),
    ("bartowski/Llama-3.2-1B-Instruct-GGUF", "Llama-3.2-1B-Instruct-IQ3_M.gguf", "text-generation", "bartowski_Llama-3.2-1B"),

    # ───────────────────────────────────────────────────────────────────────
    # text-classification  (3 existing + 22 new = 25)
    # Existing:
    ("gpustack/jina-reranker-v1-tiny-en-GGUF", "jina-reranker-v1-tiny-en-FP16.gguf", "text-classification", "gpustack_jina-reranker-v1-tiny"),
    ("cstr/fasttext-lid176-GGUF", "fasttext-lid176-f16.gguf", "text-classification", "cstr_fasttext-lid176"),
    ("cstr/cld3-GGUF", "cld3-f16.gguf", "text-classification", "cstr_cld3"),
    # New (smallest first, all < 37 MB):
    ("mradermacher/Bert-Tinny-GGUF", "Bert-Tinny.Q2_K.gguf", "text-classification", "mradermacher_Bert-Tinny"),
    ("mradermacher/bert-tiny-amd-GGUF", "bert-tiny-amd.Q2_K.gguf", "text-classification", "mradermacher_bert-tiny-amd"),
    ("mradermacher/reranker-bert-tiny-gooaq-bce-tanh-v4-GGUF", "reranker-bert-tiny-gooaq-bce-tanh-v4.Q2_K.gguf", "text-classification", "mradermacher_reranker-bert-tiny-gooaq"),
    ("VoltageVagabond/spam-classifier-liquid-Q8_0-GGUF", "spam-classifier-liquid-q8_0.gguf", "text-classification", "VoltageVagabond_spam-classifier-liquid"),
    ("mradermacher/primary-school-math-question-i1-GGUF", "primary-school-math-question.i1-IQ1_S.gguf", "text-classification", "mradermacher_primary-school-math-i1"),
    ("mradermacher/medicalcode-classifier-v1-i1-GGUF", "medicalcode-classifier-v1.i1-IQ1_S.gguf", "text-classification", "mradermacher_medicalcode-classifier-i1"),
    ("mradermacher/primary-school-math-question-GGUF", "primary-school-math-question.Q2_K.gguf", "text-classification", "mradermacher_primary-school-math-Q2K"),
    ("mradermacher/medicalcode-classifier-v1-GGUF", "medicalcode-classifier-v1.Q2_K.gguf", "text-classification", "mradermacher_medicalcode-classifier-Q2K"),
    ("mradermacher/COAL_INVOICE_ZEON-i1-GGUF", "COAL_INVOICE_ZEON.i1-IQ1_S.gguf", "text-classification", "mradermacher_COAL_INVOICE-i1"),
    ("mradermacher/CASH_AND_BANK_INVOICE-i1-GGUF", "CASH_AND_BANK_INVOICE.i1-IQ1_S.gguf", "text-classification", "mradermacher_CASH_BANK_INVOICE-i1"),
    ("mradermacher/COAL_INVOICE_ZEON-GGUF", "COAL_INVOICE_ZEON.Q2_K.gguf", "text-classification", "mradermacher_COAL_INVOICE-Q2K"),
    ("mradermacher/CASH_AND_BANK_INVOICE-GGUF", "CASH_AND_BANK_INVOICE.Q2_K.gguf", "text-classification", "mradermacher_CASH_BANK_INVOICE-Q2K"),
    ("mradermacher/NanoTitan-NLI-GGUF", "NanoTitan-NLI.Q2_K.gguf", "text-classification", "mradermacher_NanoTitan-NLI"),
    ("gpustack/jina-reranker-v1-turbo-en-GGUF", "jina-reranker-v1-turbo-en-Q2_K.gguf", "text-classification", "gpustack_jina-reranker-v1-turbo"),
    ("mradermacher/NuSentiment-i1-GGUF", "NuSentiment.i1-IQ1_S.gguf", "text-classification", "mradermacher_NuSentiment-i1"),
    ("mradermacher/ai-text-detector-hc3-GGUF", "ai-text-detector-hc3.Q2_K.gguf", "text-classification", "mradermacher_ai-text-detector-hc3"),
    ("mradermacher/malicious-url-detector-GGUF", "malicious-url-detector.Q2_K.gguf", "text-classification", "mradermacher_malicious-url-detector"),
    ("mradermacher/political-bias-classifier-GGUF", "political-bias-classifier.Q2_K.gguf", "text-classification", "mradermacher_political-bias-classifier"),
    ("mradermacher/safe-space-spam-detector-GGUF", "safe-space-spam-detector.Q2_K.gguf", "text-classification", "mradermacher_safe-space-spam-detector"),
    ("mradermacher/Mental-Health-Analysis-GGUF", "Mental-Health-Analysis.Q2_K.gguf", "text-classification", "mradermacher_Mental-Health-Analysis"),
    ("mradermacher/gibberish-detector-GGUF", "gibberish-detector.Q2_K.gguf", "text-classification", "mradermacher_gibberish-detector"),
    ("mradermacher/Nanoclass-bbc-GGUF", "Nanoclass-bbc.Q2_K.gguf", "text-classification", "mradermacher_Nanoclass-bbc"),


    # ───────────────────────────────────────────────────────────────────────
    # feature-extraction  (3 existing + 22 new = 25)
    # Existing:
    ("unsloth/bge-small-en-v1.5-GGUF", "bge-small-en-v1.5-f16.gguf", "feature-extraction", "unsloth_bge-small-en-v1.5"),
    ("ggml-org/bge-small-en-v1.5-Q8_0-GGUF", "bge-small-en-v1.5-q8_0.gguf", "feature-extraction", "ggml-org_bge-small-en-v1.5-Q8"),
    ("second-state/All-MiniLM-L6-v2-Embedding-GGUF", "all-MiniLM-L6-v2-Q2_K.gguf", "feature-extraction", "second-state_All-MiniLM-L6-v2"),
    # New (smallest first, all < 19 MB):
    ("mradermacher/cupidon-tiny-ro-i1-GGUF", "cupidon-tiny-ro.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_cupidon-tiny-ro-i1"),
    ("mradermacher/cupidon-tiny-ro-GGUF", "cupidon-tiny-ro.Q2_K.gguf", "feature-extraction", "mradermacher_cupidon-tiny-ro-Q2K"),
    ("cstr/sface-GGUF", "sface-q4_k.gguf", "feature-extraction", "cstr_sface"),
    ("mradermacher/Venusaur-GGUF", "Venusaur.Q2_K.gguf", "feature-extraction", "mradermacher_Venusaur"),
    ("mradermacher/bge-micro-v2-i1-GGUF", "bge-micro-v2.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_bge-micro-v2-i1"),
    ("mradermacher/bge-micro-v2-GGUF", "bge-micro-v2.Q2_K.gguf", "feature-extraction", "mradermacher_bge-micro-v2-Q2K"),
    ("mradermacher/Bulbasaur-GGUF", "Bulbasaur.Q2_K.gguf", "feature-extraction", "mradermacher_Bulbasaur"),
    ("mradermacher/gte-tiny-i1-GGUF", "gte-tiny.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_gte-tiny-i1"),
    ("mradermacher/msmarco-MiniLM-L6-v3-i1-GGUF", "msmarco-MiniLM-L6-v3.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_msmarco-MiniLM-v3-i1"),
    ("mradermacher/paraphrase-MiniLM-L6-v2-i1-GGUF", "paraphrase-MiniLM-L6-v2.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_paraphrase-MiniLM-i1"),
    ("mradermacher/msmarco-MiniLM-L6-cos-v5-i1-GGUF", "msmarco-MiniLM-L6-cos-v5.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_msmarco-MiniLM-cosv5-i1"),
    ("mradermacher/all-MiniLM-L6-v1-i1-GGUF", "all-MiniLM-L6-v1.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_all-MiniLM-L6-v1-i1"),
    ("mradermacher/mass-academy-faq-embedder-i1-GGUF", "mass-academy-faq-embedder.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_mass-academy-faq-i1"),
    ("mradermacher/medical-term-similarity-i1-GGUF", "medical-term-similarity.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_medical-term-i1"),
    ("mradermacher/medical_discharge_embeddings-i1-GGUF", "medical_discharge_embeddings.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_medical-discharge-i1"),
    ("mradermacher/cupidon-mini-ro-i1-GGUF", "cupidon-mini-ro.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_cupidon-mini-ro-i1"),
    ("mradermacher/multi-qa-MiniLM-L6-cos-v1-i1-GGUF", "multi-qa-MiniLM-L6-cos-v1.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_multi-qa-MiniLM-i1"),
    ("mradermacher/Multilingual-Text-Semantic-Search-Siamese-BERT-V1-i1-GGUF", "Multilingual-Text-Semantic-Search-Siamese-BERT-V1.i1-IQ1_S.gguf", "feature-extraction", "mradermacher_Multilingual-Siamese-i1"),
    ("mradermacher/msmarco-MiniLM-L6-v3-GGUF", "msmarco-MiniLM-L6-v3.Q2_K.gguf", "feature-extraction", "mradermacher_msmarco-MiniLM-v3-Q2K"),
    ("mradermacher/paraphrase-MiniLM-L6-v2-GGUF", "paraphrase-MiniLM-L6-v2.Q2_K.gguf", "feature-extraction", "mradermacher_paraphrase-MiniLM-Q2K"),
    ("mradermacher/msmarco-MiniLM-L6-cos-v5-GGUF", "msmarco-MiniLM-L6-cos-v5.Q2_K.gguf", "feature-extraction", "mradermacher_msmarco-MiniLM-cosv5-Q2K"),
    ("mradermacher/GIST-all-MiniLM-L6-v2-GGUF", "GIST-all-MiniLM-L6-v2.Q2_K.gguf", "feature-extraction", "mradermacher_GIST-all-MiniLM-Q2K"),

    # ───────────────────────────────────────────────────────────────────────
    # token-classification  (3 existing + 22 new = 25)
    # Uses NER-family + PII GGUFs across Hub (functional placement, not pipeline_tag).
    # Existing:
    ("cstr/fireredpunc-GGUF", "fireredpunc-iq4_xs.gguf", "token-classification", "cstr_fireredpunc"),
    ("cstr/fireredpunc-GGUF", "fireredpunc-q4_k.gguf", "token-classification", "cstr_fireredpunc-q4k"),
    ("cstr/pcs-xlmr-base-GGUF", "pcs-xlmr-base-iq4_xs.gguf", "token-classification", "cstr_pcs-xlmr-base"),
    # New NER/PII GGUFs (smallest first, relaxed to ~970 MB):
    ("mradermacher/NuNER-BERT-v1.0-GGUF", "NuNER-BERT-v1.0.Q2_K.gguf", "token-classification", "mradermacher_NuNER-BERT-Q2K"),
    ("cstr/bert-base-NER-GGUF", "bert-base-ner-iq4_xs.gguf", "token-classification", "cstr_bert-base-NER"),
    ("cstr/lilt-funsd-GGUF", "lilt-funsd-iq4_xs.gguf", "token-classification", "cstr_lilt-funsd"),
    ("Mike0021/pulpie-orange-small-gguf", "pulpie-orange-small-Q2_K.gguf", "token-classification", "Mike0021_pulpie-orange"),
    ("cstr/punctuate-all-GGUF", "punctuate-all-orig-q4_k.gguf", "token-classification", "cstr_punctuate-all"),
    ("mradermacher/LFM2-350M-PII-Extract-JP-GGUF", "LFM2-350M-PII-Extract-JP.IQ4_XS.gguf", "token-classification", "mradermacher_LFM2-350M-PII-JP"),
    ("cagrigungor/pii-guard-turkish-270m-gguf", "gemma-3-270m-it.Q4_K_M.gguf", "token-classification", "cagrigungor_pii-guard-turkish"),
    ("Keithsel/Aster-Vietnamese-NER-MiniLM-GGUF", "Aster-Vietnamese-NER-MiniLM-F16.gguf", "token-classification", "Keithsel_Aster-Vietnamese-NER"),
    ("cstr/xlmr-ner-hrl-GGUF", "xlmr-ner-hrl-iq4_xs.gguf", "token-classification", "cstr_xlmr-ner-hrl"),
    ("mradermacher/PII_DETECTION_MODEL-GGUF", "PII_DETECTION_MODEL.IQ4_XS.gguf", "token-classification", "mradermacher_PII_DETECTION_MODEL"),
    ("mradermacher/Nero1-0.5B-GGUF", "Nero1-0.5B.IQ4_XS.gguf", "token-classification", "mradermacher_Nero1-0.5B"),
    ("mradermacher/qwen3-0.6b-pii-detector-GGUF", "qwen3-0.6b-pii-detector.IQ4_XS.gguf", "token-classification", "mradermacher_qwen3-0.6b-pii-detector"),
    ("anish12/model_gguf_ner", "unsloth.Q4_K_M.gguf", "token-classification", "anish12_model_gguf_ner"),
    ("anish12/model_gguf_ner_0.6_e_1", "unsloth.Q4_K_M.gguf", "token-classification", "anish12_model_gguf_ner_0.6"),
    ("mradermacher/detect-pii-0.8b-v2-GGUF", "detect-pii-0.8b-v2.IQ4_XS.gguf", "token-classification", "mradermacher_detect-pii-0.8b"),
    ("distil-labs/Distil-PII-SmolLM2-135M-Instruct-gguf", "model.gguf", "token-classification", "distil-labs_Distil-PII-SmolLM2-135M"),
    ("jakobhuss/pii-extractor-gemma-3-270m-it-GGUF", "gemma-3-270m-it.F16.gguf", "token-classification", "jakobhuss_pii-extractor-gemma-3"),
    ("fffonion/xlm-roberta-ner-japanese-gguf", "xlm-roberta-ner-japanese-f16.gguf", "token-classification", "fffonion_xlm-roberta-ner-japanese"),
    ("cstr/fullstop-punc-multilang-GGUF", "fullstop-punc-q4_k.gguf", "token-classification", "cstr_fullstop-punc-multilang"),
    ("mradermacher/GRPO-NER-Lora-V0-GGUF", "GRPO-NER-Lora-V0.IQ4_XS.gguf", "token-classification", "mradermacher_GRPO-NER-Lora"),
    ("mradermacher/Nero-Qwen2.5-1.5B-Surgical-GGUF", "Nero-Qwen2.5-1.5B-Surgical.IQ4_XS.gguf", "token-classification", "mradermacher_Nero-Qwen2.5-1.5B"),
    ("mradermacher/AF-NER-I-GGUF", "AF-NER-I.IQ4_XS.gguf", "token-classification", "mradermacher_AF-NER-I"),

    # ───────────────────────────────────────────────────────────────────────
    # question-answering  (3 existing + 22 new = 25)
    # Existing:
    ("cstr/qwen3-embed-0.6b-GGUF", "qwen3-embed-0.6b-iq4_xs.gguf", "question-answering", "cstr_qwen3-embed-0.6b"),
    ("cstr/multilingual-e5-small-GGUF", "multilingual-e5-small-iq4_xs.gguf", "question-answering", "cstr_multilingual-e5-small"),
    ("cstr/bge-reranker-base-GGUF", "bge-reranker-base-iq4_xs-f7.gguf", "question-answering", "cstr_bge-reranker-base"),
    # New (smallest first, relaxed to ~610 MB):
    ("RakshitAralimatti/Mistral-7b-Lora-Medical-ChatSupport-Q8_0-GGUF", "Mistral-7b-Lora-Medical-ChatSupport-q8_0.gguf", "question-answering", "RakshitAralimatti_Medical-ChatSupport"),
    ("lewisdog/qwen3-1.7b-cogs-ask-GGUF", "qwen3-1.7b-cogs-ask-adapter-f16.gguf", "question-answering", "lewisdog_qwen3-1.7b-cogs-ask"),
    ("wenhui1127/Llama2-Chinese-7b-Chat-LoRA-F16-GGUF", "Llama2-Chinese-7b-Chat-LoRA-f16.gguf", "question-answering", "wenhui1127_Llama2-Chinese-LoRA"),
    ("geasadfg/Finetuned-DeepSeek-R1-Distill-Llama-8B-CoT-Financial-Analyst-F16-GGUF", "Finetuned-DeepSeek-R1-Distill-Llama-8B-CoT-Financial-Analyst-f16.gguf", "question-answering", "geasadfg_DeepSeek-8B-Financial"),
    ("rafaelldietrich/Mistral-7B-Business-F16-GGUF", "Mistral-7B-Business-f16.gguf", "question-answering", "rafaelldietrich_Mistral-7B-Business"),
    ("Savyasaachin/Legal-SLM-F32-GGUF", "Legal-SLM-f32.gguf", "question-answering", "Savyasaachin_Legal-SLM-F32"),
    ("mradermacher/HYZ-01-0.6B-i1-GGUF", "HYZ-01-0.6B.i1-IQ1_S.gguf", "question-answering", "mradermacher_HYZ-01-0.6B-i1"),
    ("mradermacher/next-270m-GGUF", "next-270m.Q3_K_S.gguf", "question-answering", "mradermacher_next-270m"),
    ("mradermacher/Llama-encoder-1.0B-i1-GGUF", "Llama-encoder-1.0B.i1-IQ1_S.gguf", "question-answering", "mradermacher_Llama-encoder-1B-i1"),
    ("mradermacher/HYZ-01-0.6B-GGUF", "HYZ-01-0.6B.Q2_K.gguf", "question-answering", "mradermacher_HYZ-01-0.6B-Q2K"),
    ("mradermacher/Qwen-encoder-0.5B-i1-GGUF", "Qwen-encoder-0.5B.i1-IQ1_S.gguf", "question-answering", "mradermacher_Qwen-encoder-0.5B-i1"),
    ("mradermacher/ECE-PRYMMAL-0.5B-FT-V4-MUSR-Mathis-GGUF", "ECE-PRYMMAL-0.5B-FT-V4-MUSR-Mathis.Q3_K_S.gguf", "question-answering", "mradermacher_ECE-PRYMMAL-0.5B"),
    ("mradermacher/Qwen-encoder-0.5B-GGUF", "Qwen-encoder-0.5B.Q3_K_S.gguf", "question-answering", "mradermacher_Qwen-encoder-0.5B-Q3K"),
    ("tensorblock/Qwen-encoder-0.5B-GGUF", "Qwen-encoder-0.5B-Q2_K.gguf", "question-answering", "tensorblock_Qwen-encoder-0.5B"),
    ("surya-ravindra/BioXP-0.5B-MedMCQA-Q4_K_M-GGUF", "bioxp-0.5b-medmcqa-q4_k_m.gguf", "question-answering", "surya-ravindra_BioXP-0.5B-MedMCQA"),
    ("mradermacher/inferencevision-pythia-1B-GGUF", "inferencevision-pythia-1B.Q2_K.gguf", "question-answering", "mradermacher_pythia-1B-Q2K"),
    ("tensorblock/Llama-encoder-1.0B-GGUF", "Llama-encoder-1.0B-Q2_K.gguf", "question-answering", "tensorblock_Llama-encoder-1B-Q2K"),
    ("mradermacher/Qwen-encoder-1.5B-i1-GGUF", "Qwen-encoder-1.5B.i1-IQ1_S.gguf", "question-answering", "mradermacher_Qwen-encoder-1.5B-i1"),
    ("mradermacher/GeoScholar-QA-1.2B-GGUF", "GeoScholar-QA-1.2B.Q2_K.gguf", "question-answering", "mradermacher_GeoScholar-QA-1.2B"),
    ("tensorblock/llama3.2_1b_finetuned_SQL_multitableJidouka-GGUF", "llama3.2_1b_finetuned_SQL_multitableJidouka-Q2_K.gguf", "question-answering", "tensorblock_SQL-finetune-llama3.2-1B"),
    ("mradermacher/Prototype-Virus-1B-i1-GGUF", "Prototype-Virus-1B.i1-IQ1_S.gguf", "question-answering", "mradermacher_Prototype-Virus-1B-i1"),
    ("mradermacher/tinyllama-medical-GGUF", "tinyllama-medical.Q2_K.gguf", "question-answering", "mradermacher_tinyllama-medical-Q2K"),
]


def _cluster_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for _, _, cluster, _ in GGUF_MODELS:
        counts[cluster] = counts.get(cluster, 0) + 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="data/crawled")
    ap.add_argument("--cluster", default=None,
                    help="comma-separated subset: text-generation,text-classification,"
                         "feature-extraction,token-classification,question-answering")
    ap.add_argument("--list", action="store_true", help="list selected models and exit")
    ap.add_argument("--stats", action="store_true", help="per-cluster counts and exit")
    args = ap.parse_args()

    if args.stats:
        for cluster, n in sorted(_cluster_counts().items()):
            print(f"  {cluster:<24} {n}")
        print(f"  {'TOTAL':<24} {len(GGUF_MODELS)}")
        return 0

    selected = GGUF_MODELS
    if args.cluster:
        wanted = set(c.strip() for c in args.cluster.split(",") if c.strip())
        selected = [m for m in GGUF_MODELS if m[2] in wanted]

    if args.list:
        for repo, fn, cluster, disp in selected:
            print(f"{cluster:<24} {repo}  {fn}")
        return 0

    results: list[dict] = []
    skipped = 0
    for repo, fn, cluster, disp in selected:
        dest = os.path.join(args.out_dir, cluster, f"{repo.replace('/', '_')}")
        os.makedirs(dest, exist_ok=True)
        target = os.path.join(dest, fn)
        if os.path.exists(target) and os.path.getsize(target) > 0:
            print(f"[skip] already present: {target} ({os.path.getsize(target):,} bytes)")
            skipped += 1
            continue
        print(f"\n[download] {cluster}/{disp}  -> {fn}")
        try:
            path = hf_hub_download(
                repo_id=repo,
                filename=fn,
                local_dir=dest,
                tqdm_class=tqdm,
            )
            size = os.path.getsize(path)
            print(f"[ok] {path} ({size:,} bytes)")
            results.append({"cluster": cluster, "repo_id": repo, "filename": fn, "size": size})
        except Exception as e:
            print(f"[error] {repo}/{fn}: {e}")

    print(f"\nDone. Downloaded {len(results)} new GGUF file(s); {skipped} already present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
