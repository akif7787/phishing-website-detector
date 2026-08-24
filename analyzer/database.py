"""
Lightweight SQLite Database Layer for Analysis History.
Stores and retrieves recent URL security assessments without bulky dependencies.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AnalysisDatabase:
    """
    SQLite persistence for historical phishing website analysis reports.
    """

    DEFAULT_DB_PATH = "analysis_history.db"

    @classmethod
    def get_connection(cls, db_path: Optional[str] = None) -> sqlite3.Connection:
        path = db_path or cls.DEFAULT_DB_PATH
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn

    @classmethod
    def init_db(cls, db_path: Optional[str] = None) -> None:
        """
        Initializes the SQLite schema if it does not already exist.
        """
        with cls.get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    domain TEXT,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    top_indicator TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    result_json TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_history_timestamp 
                ON analysis_history (timestamp DESC)
            """)
            conn.commit()

    @classmethod
    def save_analysis(
        cls,
        url: str,
        domain: str,
        risk_score: int,
        risk_level: str,
        risk_tier: str,
        top_indicator: Optional[str],
        result_dict: Dict[str, Any],
        db_path: Optional[str] = None,
    ) -> int:
        """
        Saves a newly completed URL analysis report.
        """
        cls.init_db(db_path)
        with cls.get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO analysis_history 
                (url, domain, risk_score, risk_level, risk_tier, top_indicator, timestamp, result_json)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)
                """,
                (
                    url,
                    domain,
                    risk_score,
                    risk_level,
                    risk_tier,
                    top_indicator or "No major threat detected",
                    json.dumps(result_dict),
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    @classmethod
    def get_recent_analyses(cls, limit: int = 20, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves the most recent URL analyses.
        """
        cls.init_db(db_path)
        results: List[Dict[str, Any]] = []
        with cls.get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, domain, risk_score, risk_level, risk_tier, top_indicator, timestamp
                FROM analysis_history
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            for row in rows:
                results.append({
                    "id": row["id"],
                    "url": row["url"],
                    "domain": row["domain"],
                    "risk_score": row["risk_score"],
                    "risk_level": row["risk_level"],
                    "risk_tier": row["risk_tier"],
                    "top_indicator": row["top_indicator"],
                    "timestamp": row["timestamp"],
                })
        return results

    @classmethod
    def get_analysis_by_id(cls, item_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves full JSON details for a specific analysis item.
        """
        cls.init_db(db_path)
        with cls.get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, result_json, timestamp
                FROM analysis_history
                WHERE id = ?
                """,
                (item_id,),
            )
            row = cursor.fetchone()
            if row:
                try:
                    data = json.loads(row["result_json"])
                    data["history_id"] = row["id"]
                    data["history_timestamp"] = row["timestamp"]
                    return data
                except Exception:
                    return None
        return None

    @classmethod
    def clear_history(cls, db_path: Optional[str] = None) -> bool:
        """
        Clears all records in analysis history.
        """
        cls.init_db(db_path)
        with cls.get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM analysis_history")
            conn.commit()
            return True
