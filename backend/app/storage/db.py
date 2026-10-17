"""Report storage (SQLite by default, Postgres via DATABASE_URL) with retention purge."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlmodel import Field, Session, SQLModel, create_engine, delete, select

from app.models.schemas import Report, ReportSummary


class ReportRow(SQLModel, table=True):
    __tablename__ = "reports"

    id: str = Field(primary_key=True)
    created_at: datetime = Field(index=True)
    input_type: str
    title: str
    score: int
    label: str
    data: str


class ReportStore:
    def __init__(self, url: str) -> None:
        if url.startswith("sqlite:///"):
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, connect_args=connect_args)
        SQLModel.metadata.create_all(self.engine)

    def save(self, report: Report) -> None:
        row = ReportRow(
            id=report.id,
            created_at=report.created_at,
            input_type=report.input_type,
            title=report.title[:300],
            score=report.verdict.score,
            label=report.verdict.label.value,
            data=report.model_dump_json(),
        )
        with Session(self.engine) as s:
            s.add(row)
            s.commit()

    def get(self, report_id: str) -> Report | None:
        with Session(self.engine) as s:
            row = s.get(ReportRow, report_id)
            return Report.model_validate_json(row.data) if row else None

    def recent(self, limit: int = 20) -> list[ReportSummary]:
        with Session(self.engine) as s:
            rows = s.exec(select(ReportRow).order_by(ReportRow.created_at.desc()).limit(limit)).all()
        return [
            ReportSummary(id=r.id, created_at=r.created_at, input_type=r.input_type, title=r.title, score=r.score, label=r.label)
            for r in rows
        ]

    def delete(self, report_id: str) -> bool:
        with Session(self.engine) as s:
            row = s.get(ReportRow, report_id)
            if not row:
                return False
            s.delete(row)
            s.commit()
            return True

    def purge_older_than(self, days: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=days)
        with Session(self.engine) as s:
            result = s.exec(delete(ReportRow).where(ReportRow.created_at < cutoff))
            s.commit()
            return result.rowcount or 0
