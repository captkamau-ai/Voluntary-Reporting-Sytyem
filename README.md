# Voluntary-Reporting-System
Thus is a system designed for air operators to help them report hazards ad incidents internally to boost on safety and regulatory compliance. It is designed to be anonymous and can easily be integrated to their existing infrastructure. 
vhr-system/
├─ backend/
│ ├─ app/main.py
│ ├─ app/models.py
│ ├─ app/schemas.py
│ ├─ app/crud.py
│ ├─ app/auth.py
│ ├─ app/deps.py
│ ├─ app/config.py
│ ├─ app/storage.py
│ ├─ app/audit.py
│ ├─ migrations/
│ └─ Dockerfile
├─ frontend/
│ └─ src/App.jsx
├─ docker-compose.yml
├─ README.md
from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship


class HazardReport(SQLModel, table=True):
id: Optional[int] = Field(default=None, primary_key=True)
created_at: datetime = Field(default_factory=datetime.utcnow)
updated_at: datetime = Field(default_factory=datetime.utcnow)


# reporter info (nullable for anonymity)
reporter_name: Optional[str] = None
reporter_email: Optional[str] = None
reporter_identified: bool = False # True if reporter allowed ID to be stored


# occurrence details
occurrence_datetime: Optional[datetime] = None
location: Optional[str] = None
flight_phase: Optional[str] = None
aircraft_type: Optional[str] = None
registration: Optional[str] = None


# report content
narrative: str
contributing_factors: Optional[str] = None
immediate_actions: Optional[str] = None
suggested_mitigation: Optional[str] = None


# classification
severity: Optional[str] = None # e.g. Low/Medium/High
active: bool = True
status: str = "new" # new, under_investigation, closed


class Attachment(SQLModel, table=True):
id: Optional[int] = Field(default=None, primary_key=True)
report_id: int = Field(foreign_key="hazardreport.id")
filename: str
storage_path: str
### `app/schemas.py` (Pydantic request/response models)
```python
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime


class HazardReportCreate(BaseModel):
occurrence_datetime: Optional[datetime]
location: Optional[str]
flight_phase: Optional[str]
aircraft_type: Optional[str]
registration: Optional[str]


narrative: str
contributing_factors: Optional[str]
immediate_actions: Optional[str]
suggested_mitigation: Optional[str]


severity: Optional[str]


# reporter
reporter_name: Optional[str]
reporter_email: Optional[EmailStr]
reporter_identified: Optional[bool] = False


class HazardReportRead(HazardReportCreate):
id: int
created_at: datetime
status: str
### `app/crud.py`
```python
from sqlmodel import Session, select
from .models import HazardReport, Attachment


def create_report(session: Session, report: HazardReport):
session.add(report)
session.commit()
session.refresh(report)
return report


def get_report(session: Session, report_id: int):
return session.get(HazardReport, report_id)


def list_reports(session: Session, offset: int = 0, limit: int = 50):
return session.exec(select(HazardReport).offset(offset).limit(limit)).all()
### `app/storage.py` (simple file storage)
```python
import os
from uuid import uuid4


UPLOAD_DIR = os.getenv("UPLOAD_DIR", "./uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def save_attachment(filename: str, file_bytes: bytes) -> str:
# sanitize filename in production
uid = uuid4().hex
_, ext = os.path.splitext(filename)
fname = f"{uid}{ext}"
path = os.path.join(UPLOAD_DIR, fname)
with open(path, "wb") as f:
f.write(file_bytes)
return path
### `app/auth.py` (very small JWT helper — expand for production)
```python
from datetime import datetime, timedelta
from jose import jwt


SECRET = "REPLACE_THIS_WITH_A_SECURE_RANDOM_KEY"
ALGORITHM = "HS256"


def create_access_token(subject: str, expires_delta: int = 60*60*24):
to_encode = {"sub": subject, "exp": datetime.utcnow() + timedelta(seconds=expires_delta)}
return jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)
### `app/main.py` (API endpoints)
```python
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from sqlmodel import Session, create_engine, SQLModel
from .models import HazardReport, Attachment
from .schemas import HazardReportCreate, HazardReportRead
from .crud import create_report, get_report, list_reports
from .storage import save_attachment


app = FastAPI(title="Voluntary Hazard Reporting")


DATABASE_URL = "sqlite:///./vhr.db"
engine = create_engine(DATABASE_URL, echo=False)


@app.on_event("startup")
def on_startup():
SQLModel.metadata.create_all(engine)


def get_session():
with Session(engine) as session:
yield session


@app.post("/reports", response_model=HazardReportRead)
async def submit_report(payload: HazardReportCreate, files: list[UploadFile] | None = File(None), session: Session = Depends(get_session)):
# create model
model = HazardReport(**payload.dict())
created = create_report(session, model)


# attachments
if files:
for f in files:
b = await f.read()
path = save_attachment(f.filename, b)
att = Attachment(report_id=created.id, filename=f.filename, storage_path=path)
session.add(att)
session.commit()


return created


@app.get("/reports/{report_id}", response_model=HazardReportRead)
def read_report(report_id: int, session: Session = Depends(get_session)):
r = get_report(session, report_id)
if not r:
raise HTTPException(status_code=404, detail="Report not found")
return r


@app.get("/reports")
def all_reports(offset: int = 0, limit: int = 50, session: Session = Depends(get_session)):
return list_reports(session, offset, limit)
