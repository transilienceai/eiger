FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir uv
COPY pyproject.toml uv.lock LICENSE ./
COPY halcyon ./halcyon
COPY labs ./labs
COPY mcp.json ./mcp.json
RUN uv sync --frozen --no-dev
# Bake the ONNX embedding model into the image so the first /api/ask never triggers
# a slow, thrashing runtime download. Uses the same default chromadb EF the app uses.
RUN uv run python -c "import chromadb; c=chromadb.Client().get_or_create_collection('warm'); c.add(ids=['1'], documents=['warmup']); c.query(query_texts=['warmup'], n_results=1)"
EXPOSE 8000
CMD ["uv", "run", "uvicorn", "halcyon.main:app", "--host", "0.0.0.0", "--port", "8000"]
