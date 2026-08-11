# DynaHug behavioral-oracle image.
#
# DynaHug (Nambiar/Pradhan/Soremekun, "Malicious ML Model Detection by
# Learning Dynamic Behaviors", arXiv:2604.19438; upstream
# DynaHug-Detector/DynaHug) is a dynamic ML classifier for pre-trained
# models: it executes the model load in a sandbox, collects system-call
# behavior with strace, extracts presence/frequency syscall features, and
# flags anomalous files with a One-Class SVM.
#
# Built FROM the shared base image (T0.2, ships Python 3.13 + torch + strace).
# The wrapper (T0.7) reimplements the upstream pipeline
# (main.py -> src/analysis.py -> src/inference.py -> src/strace_analyzer.py ->
# classifier/svm.py) faithful to the paper's default DynaHug model
# (text-generation OCSVM, presence+frequency features, count-pass strace)
# pinned at upstream commit 8ff8174. The full upstream tree is 5.5 GB (3.8 GB
# is text-generation model artifacts), so only the required pinned files are
# pulled directly from raw.githubusercontent.com into /opt/dynahug:

#   LICENSE, classifier/syscalls.txt,
#   classifier/models/text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/
#   OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01/{oneclass_svm_model,scaler,vectorizer}.pkl
#
# and kept as a reference. scikit-learn/joblib are pinned to the versions in
# upstream requirements.txt so the serialized artifacts load reproducibly
# (their model pickles were trained with scikit-learn 1.7.1 / joblib 1.5.2).

FROM regenbench/base:0.2.0

ARG DYNAHUG_COMMIT=8ff8174eaf54175a7fc3b90730faf334fb767e0b
ENV DYNAHUG_COMMIT=${DYNAHUG_COMMIT}

RUN python3.13 -m pip install --no-cache-dir \
        scikit-learn==1.7.1 \
        joblib==1.5.2

# Fetch the pinned DynaHug files (reference + model artifacts).
RUN DYN_PREFIX="https://raw.githubusercontent.com/DynaHug-Detector/DynaHug/${DYNAHUG_COMMIT}" \
    && MODEL_REL="classifier/models/text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01" \
    && mkdir -p /opt/dynahug/classifier/models \
    && curl -fsSL "${DYN_PREFIX}/LICENSE" -o /opt/dynahug/LICENSE \
    && curl -fsSL "${DYN_PREFIX}/classifier/syscalls.txt" -o /opt/dynahug/classifier/syscalls.txt \
    && mkdir -p "/opt/dynahug/${MODEL_REL}" \
    && for f in oneclass_svm_model.pkl scaler.pkl vectorizer.pkl; do \
         curl -fsSL "${DYN_PREFIX}/${MODEL_REL}/${f}" -o "/opt/dynahug/${MODEL_REL}/${f}"; \
       done

# Verify the artifacts load (pinned scikit-learn/joblib) and strace works
# under rootless podman (ptrace) before relying on it.
# NOTE: single-line `python3.13 -c` (not a heredoc) so it builds with the
# classic (non-BuildKit) imagebuilder used by podman on CI.
RUN python3.13 -c 'import joblib,os; base="/opt/dynahug/classifier/models/text-generation/2000_benign_data_presence_frequency_new_logs_std_scaler_nomean_best/OneClassSVM/params-gamma_0.1_kernel_rbf_nu_0.01"; m=joblib.load(os.path.join(base,"oneclass_svm_model.pkl")); v=joblib.load(os.path.join(base,"vectorizer.pkl")); s=joblib.load(os.path.join(base,"scaler.pkl")); print("model %s | vectorizer %s | n_feats %s" % (type(m).__name__, type(v).__name__, len(v.get_feature_names_out())))'
RUN strace -c -f -o /dev/null true

COPY loader.py /usr/local/bin/dynahug-loader
COPY wrapper.py /usr/local/bin/dynahug-wrapper

ENTRYPOINT ["python3.13", "/usr/local/bin/dynahug-wrapper"]