from datetime import date, datetime
import os
from typing import Any

import psycopg
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/tally", tags=["tally"])

DATABASE_URL = os.getenv("DATABASE_URL")


def _serialize(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


@router.get("/submissions/{submission_id}")
def get_submission(submission_id: int) -> dict:
    if not DATABASE_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL is not configured")

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    company_code,
                    submitted_at,
                    company_name,
                    cud_number,
                    status,
                    created_at,
                    updated_at
                FROM form_submissions
                WHERE id = %s
                """,
                (submission_id,),
            )
            submission = cur.fetchone()

            if not submission:
                raise HTTPException(status_code=404, detail="Submission not found")

            cur.execute(
                """
                SELECT
                    id,
                    shareholder_index,
                    full_name,
                    date_of_birth,
                    nationality,
                    place_of_birth,
                    tax_id,
                    address,
                    email,
                    created_at,
                    updated_at
                FROM shareholders
                WHERE submission_id = %s
                ORDER BY shareholder_index
                """,
                (submission_id,),
            )
            shareholder_rows = cur.fetchall()

            cur.execute(
                """
                SELECT
                    id,
                    shareholder_id,
                    document_type,
                    file_name,
                    file_url,
                    file_reference,
                    mime_type,
                    created_at
                FROM uploaded_documents
                WHERE submission_id = %s
                ORDER BY id
                """,
                (submission_id,),
            )
            document_rows = cur.fetchall()

    shareholders = [
        {
            "shareholder_id": row[0],
            "shareholder_index": row[1],
            "full_name": row[2],
            "date_of_birth": _serialize(row[3]),
            "nationality": row[4],
            "place_of_birth": row[5],
            "tax_id": row[6],
            "address": row[7],
            "email": row[8],
            "created_at": _serialize(row[9]),
            "updated_at": _serialize(row[10]),
        }
        for row in shareholder_rows
    ]

    documents = [
        {
            "document_id": row[0],
            "shareholder_id": row[1],
            "document_type": row[2],
            "file_name": row[3],
            "file_url": row[4],
            "file_reference": row[5],
            "mime_type": row[6],
            "created_at": _serialize(row[7]),
        }
        for row in document_rows
    ]

    return {
        "submission_id": submission[0],
        "company_code": submission[1],
        "submitted_at": _serialize(submission[2]),
        "company_name": submission[3],
        "cud_number": submission[4],
        "status": submission[5],
        "created_at": _serialize(submission[6]),
        "updated_at": _serialize(submission[7]),
        "shareholders": shareholders,
        "documents": documents,
    }
