# MeshEmbed Node - image for external GPU operators
#
# Quick start (first time):
#   docker run -d \
#     -e MESHEMBED_BACKEND=https://meshembed.clusterhive.io \
#     -e MESHEMBED_NODE_API_KEY=msh_node_xxx \
#     -e MESHEMBED_NODE_ID=$(cat /proc/sys/kernel/random/uuid) \
#     --gpus all \
#     clusterhive/meshembed-node:latest
#
# With an NVIDIA GPU the host driver must be >= 450.x and have nvidia-container-toolkit installed.
# Without a GPU, runs on CPU (slower but functional for testing).

FROM python@sha256:a0779d7c12fc20be6ec6b4ddc901a4fd7657b8a6bc9def9d3fde89ed5efe0a3d

WORKDIR /app

# Install minimal system dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional GPU metrics - install pynvml when an NVIDIA runtime is available.
RUN pip install --no-cache-dir "pynvml>=11.5" || true

# Copy daemon code.
COPY pyproject.toml .
COPY meshembed_node/ ./meshembed_node/

# Pre-warm the model (downloads ~130MB at build time; cached in the image).
# This way the first container start does not pay the download latency.
ARG MESHEMBED_MODEL=intfloat/multilingual-e5-small
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${MESHEMBED_MODEL}')"

# Required runtime environment variables (NOT in the image - secrets).
# MESHEMBED_NODE_API_KEY  - key obtained after `meshembed-node register`
# MESHEMBED_NODE_ID       - persistent node UUID (generate once, store)
ENV MESHEMBED_BACKEND=https://meshembed.clusterhive.io \
    MESHEMBED_MODEL=intfloat/multilingual-e5-small \
    MESHEMBED_POLL_MIN_S=1 \
    MESHEMBED_POLL_MAX_S=30 \
    MESHEMBED_MAX_CHUNKS=1 \
    MESHEMBED_AGENT_VERSION=0.2.0 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "meshembed_node", "run"]
