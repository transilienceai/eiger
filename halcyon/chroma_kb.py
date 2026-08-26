from typing import Any

import chromadb

from halcyon.kb import Chunk


class ChromaKB:
    """KnowledgeBase backed by an in-process, ephemeral ChromaDB collection."""

    def __init__(self, collection: str = "halcyon") -> None:
        self._client = chromadb.Client()
        self._name = collection
        self._collection = self._client.get_or_create_collection(collection)
        self._seq = 0

    def add(self, text: str, provenance: str, access: str = "public",
            owner_session: str = "") -> Chunk:
        self._seq += 1
        chunk_id = f"c{self._seq:04d}"
        self._collection.add(
            ids=[chunk_id],
            documents=[text],
            metadatas=[{
                "provenance": provenance,
                "access": access,
                "owner_session": owner_session or "",
            }],
        )
        return Chunk(chunk_id, text, provenance, access, owner_session)

    def retrieve(self, query: str, session_id: str, k: int = 3) -> list[Chunk]:
        results = self._collection.query(query_texts=[query], n_results=k)
        ids = results["ids"][0] if results["ids"] else []
        documents = results["documents"][0] if results["documents"] else []
        metadatas = results["metadatas"][0] if results["metadatas"] else []
        chunks = []
        for chunk_id, text, metadata in zip(ids, documents, metadatas):
            meta: Any = metadata or {}
            chunks.append(Chunk(
                chunk_id,
                text,
                str(meta.get("provenance", "trusted")),
                str(meta.get("access", "public")),
                str(meta.get("owner_session", "")),
            ))
        return chunks

    def seed(self, fixtures: list[dict]) -> None:
        for f in fixtures:
            self.add(f["text"], f.get("provenance", "trusted"),
                      f.get("access", "public"), f.get("owner_session", ""))

    def clear(self) -> None:
        self._client.delete_collection(self._name)
        self._collection = self._client.get_or_create_collection(self._name)
        self._seq = 0

    def list_own(self, session_id: str) -> list[Chunk]:
        got = self._collection.get(
            where={"$and": [{"provenance": "user"}, {"owner_session": session_id}]}
        )
        ids = got.get("ids") or []
        documents = got.get("documents") or []
        metadatas = got.get("metadatas") or []
        out = []
        for chunk_id, text, metadata in zip(ids, documents, metadatas):
            meta: Any = metadata or {}
            out.append(Chunk(chunk_id, text, "user", str(meta.get("access", "public")),
                             session_id))
        out.sort(key=lambda c: c.id)
        return out

    def delete_own(self, session_id: str, chunk_id: str) -> bool:
        # Scoped delete: the where-clause is the guard. A bare delete(ids=...)
        # would let a caller remove documents that are not theirs.
        if not any(c.id == chunk_id for c in self.list_own(session_id)):
            return False
        self._collection.delete(ids=[chunk_id])
        return True
