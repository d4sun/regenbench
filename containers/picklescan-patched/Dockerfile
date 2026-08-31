FROM regenbench/picklescan:latest
# P4.2 synthetic patch: add IPython.utils.process.system rule
# This would be a real denylist entry in PickleScan's rules/ directory.
# For demo, we inject via wrapper env that forces detection of this module.
COPY patched-rule.yaml /opt/picklescan/patched-rule.yaml
ENV PICKLESCAN_PATCHED_RULE=/opt/picklescan/patched-rule.yaml
