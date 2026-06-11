from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, date
from typing import Optional, Dict, Any

# Structural taxonomy choices as required by ICAO ADREP
class SafetyReportCreate(BaseModel):
    reporter_type: str = Field(..., description="e.g., Flight Crew, Cabin Crew, Maintenance, Ground Ops")
    occurrence_date: date
    flight_phase: str = Field(..., description="Takeoff, Cruise, Approach, Landing, Maintenance, Hover")
    location_icao: str = Field("HKNW", min_length=4, max_length=4, description="4-letter ICAO code")
    standard_taxonomy_tag: str = Field(..., description="ADREP code: e.g., BIRD (Bird strike), ARC (Abnormal Runway Contact)")
    hazard_description: str = Field(..., min_length=15, description="Narrative description of the hazard")
    is_confidential: bool = True

    # Pydantic model configuration for real-world payload examples
    class Config:
        json_schema_extra = {
            "example": {
                "reporter_type": "Flight Crew",
                "occurrence_date": "2026-06-11",
                "flight_phase": "Approach",
                "location_icao": "HKNW",
                "standard_taxonomy_tag": "BIRD",
                "hazard_description": "Encountered a flock of large birds at 500ft on short final approach. Unharmed, but missed approach executed.",
                "is_confidential": True
            }
        }

# Isolated data model for protected identity routing (FAA ASAP alignment)
class ReporterIdentity(BaseModel):
    reporter_name: str
    employee_id: str
    reporter_email: EmailStr
    import uuid
import secrets
import hashlib
from typing import Tuple
from schemas import SafetyReportCreate, ReporterIdentity

class IngestionPipeline:
    @staticmethod
    def generate_secure_uid() -> str:
        """Generates an un-traceable, secure UID for the safety report."""
        unique_base = f"{uuid.uuid4()}-{secrets.token_hex(8)}"
        return hashlib.sha256(unique_base.encode()).hexdigest()[:16]

    @classmethod
    def process_incoming_submission(
        cls, 
        report_data: SafetyReportCreate, 
        identity_data: Optional[ReporterIdentity] = None
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        
        # 1. Generate the isolated cross-reference ID
        report_uid = cls.generate_secure_uid()
        
        # 2. Package the De-Identified Safety Report (Safe for Analysts & System Processors)
        de_identified_report = report_data.model_dump()
        de_identified_report["report_uid"] = report_uid
        de_identified_report["submission_date"] = datetime.utcnow()
        
        # 3. Package Identity Data ONLY if it isn't an anonymous submission
        processed_identity = None
        if identity_data and report_data.is_confidential:
            processed_identity = identity_data.model_dump()
            # The report_uid link is known only to the secure identity table
            processed_identity["associated_uid"] = report_uid
            
        return de_identified_report, processed_identity
        from fastapi import FastAPI, HTTPException, status, Depends
from typing import Optional
from schemas import SafetyReportCreate, ReporterIdentity
from pipeline import IngestionPipeline

app = FastAPI(
    title="SDCPS Core Engine - Phase 2",
    description="Compliant with ICAO Annex 19, Doc 10159 & FAA Part 5 Standards",
    version="1.0.0"
)

# Mock databases representing isolated network storage tiers
SAFETY_REPORTS_DB = []
SECURE_IDENTITIES_DB = []

@app.post(
    "/api/v1/submit-report", 
    status_code=status.HTTP_201_CREATED,
    summary="Ingest new safety / hazard event"
)
async def submit_safety_report(
    report: SafetyReportCreate, 
    identity: Optional[ReporterIdentity] = None
):
    # Enforce data protection policy rules
    if not report.is_confidential and identity is not None:
        raise HTTPException(
            status_code=400, 
            detail="Non-confidential reports must not pass identity signatures into the pipeline context."
        )
        
    # Execute Phase 2 separation mechanism
    clean_report, secure_identity = IngestionPipeline.process_incoming_submission(
        report_data=report, 
        identity_data=identity
    )
    
    # Save partitioned data segments to isolated databases
    SAFETY_REPORTS_DB.append(clean_report)
    if secure_identity:
        SECURE_IDENTITIES_DB.append(secure_identity)
        
    return {
        "status": "Success",
        "message": "Safety data processed and securely de-identified.",
        "assigned_uid": clean_report["report_uid"],
        "requires_review": True
    }

@app.get("/api/v1/analytical-vault", summary="View cleared data logs (No personal attributes)")
async def get_analytical_data():
    # Only returns safe data; identities are completely decoupled
    return SAFETY_REPORTS_DB
    # risk_processor.py
from enum import Enum
from pydantic import BaseModel, Field, field_validator

class ProbabilityEnum(str, Enum):
    A = "A"  # Frequent
    B = "B"  # Occasional
    C = "C"  # Remote
    D = "D"  # Improbable
    E = "E"  # Extremely Improbable

class SeverityEnum(int, Enum):
    CATASTROPHIC = 5
    HAZARDOUS = 4
    MAJOR = 3
    MINOR = 2
    NEGLIGIBLE = 1

class RiskAssessmentInput(BaseModel):
    report_uid: str
    probability: ProbabilityEnum
    severity: SeverityEnum
    swiss_cheese_barrier: str = Field(..., description="Failed layer: Technology, Training, Supervision, or Regulations")

class RiskAssessmentResult(BaseModel):
    report_uid: str
    risk_index: str  # e.g., "5A", "3C"
    tolerability: str # UNACCEPTABLE, TOLERABLE, ACCEPTABLE
    action_required: bool
    swiss_cheese_barrier: str

class SafetyRiskEngine:
    # 5x5 Matrix definition mapping to standard ICAO Doc 9859 frameworks
    MATRIX = {
        5: {"A": "UNACCEPTABLE", "B": "UNACCEPTABLE", "C": "UNACCEPTABLE", "D": "TOLERABLE", "E": "TOLERABLE"},
        4: {"A": "UNACCEPTABLE", "B": "UNACCEPTABLE", "C": "TOLERABLE", "D": "TOLERABLE", "E": "TOLERABLE"},
        3: {"A": "UNACCEPTABLE", "B": "TOLERABLE", "C": "TOLERABLE", "D": "TOLERABLE", "E": "ACCEPTABLE"},
        2: {"A": "TOLERABLE", "B": "TOLERABLE", "C": "TOLERABLE", "D": "ACCEPTABLE", "E": "ACCEPTABLE"},
        1: {"A": "TOLERABLE", "B": "ACCEPTABLE", "C": "ACCEPTABLE", "D": "ACCEPTABLE", "E": "ACCEPTABLE"}
    }

    @classmethod
    def evaluate_risk(cls, assessment: RiskAssessmentInput) -> RiskAssessmentResult:
        severity_val = assessment.severity.value
        prob_val = assessment.probability.value
        
        # Calculate Risk Index string (e.g., "5A")
        risk_index = f"{severity_val}{prob_val}"
        
        # Fetch tolerability from the standard matrix grid
        tolerability = cls.MATRIX[severity_val][prob_val]
        
        # Determine if mitigation/action tracking is mandatory
        action_required = tolerability in ["UNACCEPTABLE", "TOLERABLE"]
        
        return RiskAssessmentResult(
            report_uid=assessment.report_uid,
            risk_index=risk_index,
            tolerability=tolerability,
            action_required=action_required,
            swiss_cheese_barrier=assessment.swiss_cheese_barrier
        )
        # Add these updates to your existing main.py file
from fastapi import APIRouter, HTTPException, status
from risk_processor import RiskAssessmentInput, RiskAssessmentResult, SafetyRiskEngine

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Management & Processing"])

# Mock database to hold processed risks
RISK_ASSESSMENTS_DB = {}

@router.post(
    "/assess", 
    response_model=RiskAssessmentResult, 
    status_code=status.HTTP_200_OK,
    summary="Process an ingested hazard through the ICAO 5x5 Safety Risk Matrix"
)
async def assess_hazard_risk(assessment: RiskAssessmentInput):
    # In a production app, you would first verify if assessment.report_uid exists in SAFETY_REPORTS_DB
    
    # Process the risk using the matrix rules engine
    result = SafetyRiskEngine.evaluate_risk(assessment)
    
    # Commit result to our risk database
    RISK_ASSESSMENTS_DB[result.report_uid] = result.model_dump()
    
    return result

@router.get(
    "/dashboard-summary",
    summary="Fetch analytical breakdown of risk states across the operation"
)
async def get_risk_summary():
    # Counts occurrences of each category to fuel the front-end dashboard widgets
    summary = {"UNACCEPTABLE": 0, "TOLERABLE": 0, "ACCEPTABLE": 0}
    for item in RISK_ASSESSMENTS_DB.values():
        summary[item["tolerability"]] += 1
    return {
        "total_assessed_hazards": len(RISK_ASSESSMENTS_DB),
        "status_distribution": summary
    }

# Remember to include this router in your core FastAPI application instantiation:
# app.include_router(router)
# spi_engine.py
from datetime import datetime, timedelta
from typing import List, Dict, Any

class SPIMonitor:
    # Pre-defined monthly thresholds for critical ICAO ADREP taxonomy markers
    ALERT_THRESHOLDS = {
        "BIRD": 3,     -- Bird Strikes
        "SCF-NP": 2,   -- System/Component Failure (Non-Powerplant)
        "ARC": 1,      -- Abnormal Runway Contact
        "RE": 1        -- Runway Excursion
    }

    @classmethod
    def calculate_monthly_metrics(cls, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyzes active reports from the last 30 days to flag SPI breaches."""
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        counts = {tag: 0 for tag in cls.ALERT_THRESHOLDS.keys()}
        triggered_alerts = []

        # Count occurrences within the time window
        for report in reports:
            # Handle both datetime objects and string parsing safely
            sub_date = report["submission_date"]
            if isinstance(sub_date, str):
                sub_date = datetime.fromisoformat(sub_date)

            if sub_date >= thirty_days_ago:
                tag = report.get("standard_taxonomy_tag")
                if tag in counts:
                    counts[tag] += 1

        # Check against regulatory threshold limits
        for tag, count in counts.items():
            threshold = cls.ALERT_THRESHOLDS[tag]
            if count >= threshold:
                triggered_alerts.append({
                    "taxonomy_tag": tag,
                    "current_count": count,
                    "threshold_limit": threshold,
                    "severity": "CRITICAL" if count > threshold else "WARNING",
                    "action_required": f"Review active {tag} mitigations immediately."
                })

        return {
            "evaluation_period": "Past 30 Days",
            "metrics": counts,
            "alerts_triggered": triggered_alerts,
            "system_status": "ALERT_ACTIVE" if triggered_alerts else "NORMAL"
        }
        # feedback_engine.py
from typing import Dict, Optional

class ClosedLoopFeedback:
    # A mock internal secure mapping system representing cross-network queries
    @staticmethod
    def dispatch_closure_notice(
        report_uid: str, 
        action_taken: str, 
        identities_db: list
    ) -> Optional[Dict[str, str]]:
        """
        Locates the decoupled reporter identity using the secure UID link 
        and generates an automated notification profile.
        """
        target_identity = None
        for identity in identities_db:
            if identity.get("associated_uid") == report_uid:
                target_identity = identity
                break

        if not target_identity:
            # Report was submitted completely anonymously; no feedback loop possible
            return None

        # Build compliance communication package
        return {
            "recipient_email": target_identity["reporter_email"],
            "recipient_name": target_identity["reporter_name"],
            "subject": f"Safety Action Complete: [Ref: #{report_uid}]",
            "body": (
                f"Dear {target_identity['reporter_name']},\n\n"
                f"Thank you for submitting safety report #{report_uid}. Your voluntary "
                f"contribution has been processed under our non-punitive Just Culture policy.\n\n"
                f"**Resolution Action Taken:** {action_taken}\n\n"
                f"Your report helps keep our airspace safe.\n\n"
                f"Best regards,\nSafety Management Office"
            )
        }
        # Add these updates to your existing main.py structure
from fastapi import APIRouter, Body
from spi_engine import SPIMonitor
from feedback_engine import ClosedLoopFeedback
from main import SAFETY_REPORTS_DB, SECURE_IDENTITIES_DB # Re-importing our mock data architecture

router = APIRouter(prefix="/api/v1/assurance", tags=["Safety Assurance & SPIs"])

@router.get("/spi-status", summary="Evaluate active SPI metrics against ICAO limits")
async def get_spi_report():
    # Pass our global report list into the analysis engine
    analysis = SPIMonitor.calculate_monthly_metrics(SAFETY_REPORTS_DB)
    return analysis

@router.post("/close-action", summary="Resolve a hazard and trigger a reporter alert package")
async def close_safety_action(
    report_uid: str = Body(..., embed=True),
    action_taken: str = Body(..., embed=True)
):
    # Process communication without pulling identity details into core logs
    notification_payload = ClosedLoopFeedback.dispatch_closure_notice(
        report_uid=report_uid,
        action_taken=action_taken,
        identities_db=SECURE_IDENTITIES_DB
    )

    if not notification_payload:
        return {
            "report_uid": report_uid,
            "status": "CLOSED",
            "feedback_dispatched": False,
            "note": "Report was submitted completely anonymously. No contact info available."
        }

    # In production, you would trigger an async background worker task here to send the actual email 
    return {
        "report_uid": report_uid,
        "status": "CLOSED",
        "feedback_dispatched": True,
        "dispatched_to": notification_payload["recipient_email"],
        "preview": notification_payload["body"]
    }

# App registry update: app.include_router(router)
# export_engine.py
import json
import csv
from io import StringIO
from datetime import datetime
from typing import List, Dict, Any

class RegulatoryExportEngine:
    
    @staticmethod
    def map_to_kcaa_faa_schema(reports: List[Dict[str, Any]], risk_db: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Transforms internal application logs into standard regulatory formats."""
        export_records = []
        
        for report in reports:
            uid = report["report_uid"]
            # Pull calculated risk metadata from Phase 3 database context
            risk_meta = risk_db.get(uid, {})
            
            # Formats dates cleanly into ISO 8601 strings required for international civil aviation reporting
            sub_date = report["submission_date"]
            if isinstance(sub_date, datetime):
                sub_date = sub_date.isoformat()

            record = {
                "RegulatoryReference": f"SDCPS-REG-{uid[:8].upper()}",
                "ObservationDate": str(report["occurrence_date"]),
                "ReportingSystemTimestamp": sub_date,
                "ReporterCategory": report["reporter_type"],
                "LocationICAO": report["location_icao"],
                "OperationalPhase": report["flight_phase"],
                "ICAO_ADREP_TaxonomyCode": report["standard_taxonomy_tag"],
                "SafetyRiskIndex": risk_meta.get("risk_index", "UNASSESSED"),
                "TolerabilityStatus": risk_meta.get("tolerability", "PENDING_REVIEW"),
                "SwissCheeseDeficiencyLayer": risk_meta.get("swiss_cheese_barrier", "UNKNOWN"),
                "DeIdentifiedNarrative": report["hazard_description"]
            }
            export_records.append(record)
            
        return export_records

    @classmethod
    def generate_json_export(cls, reports: List[Dict[str, Any]], risk_db: Dict[str, Any]) -> str:
        """Generates a structured JSON string optimized for regulatory API ingestion."""
        compliant_data = cls.map_to_kcaa_faa_schema(reports, risk_db)
        payload = {
            "ExportMetadata": {
                "SystemIdentifier": "Eagles-Aviation-SDCPS-v1",
                "ExportTimestamp": datetime.utcnow().isoformat(),
                "RegulatoryStandard": "ICAO Annex 19 / FAA 14 CFR Part 5",
                "RecordCount": len(compliant_data)
            },
            "SafetyDataLogs": compliant_data
        }
        return json.dumps(payload, indent=4)

    @classmethod
    def generate_csv_export(cls, reports: List[Dict[str, Any]], risk_db: Dict[str, Any]) -> StringIO:
        """Generates a flat CSV file memory-stream optimized for inspector spreadsheet reviews."""
        compliant_data = cls.map_to_kcaa_faa_schema(reports, risk_db)
        csv_buffer = StringIO()
        
        if not compliant_data:
            return csv_buffer
            
        headers = compliant_data[0].keys()
        writer = csv.DictWriter(csv_buffer, fieldnames=headers)
        
        writer.writeheader()
        for row in compliant_data:
            writer.writerow(row)
            
        csv_buffer.seek(0)
        return csv_buffer
        # Final endpoints addition to your main.py server setup
from fastapi import APIRouter, Response, HTTPException, status
from fastapi.responses import StreamingResponse
from export_engine import RegulatoryExportEngine
# Import live runtime mock databases from your environment setup
from main import SAFETY_REPORTS_DB
from risk_processor import RISK_ASSESSMENTS_DB 

router = APIRouter(prefix="/api/v1/audit", tags=["Regulatory Compliance & Audits"])

@router.get(
    "/export/json", 
    summary="Download ICAO Annex 19/FAA Part 5 compliant JSON data package"
)
async def export_json_audit_package():
    if not SAFETY_REPORTS_DB:
        raise HTTPException(status_code=404, detail="No operational records found to build export package.")
        
    json_data = RegulatoryExportEngine.generate_json_export(SAFETY_REPORTS_DB, RISK_ASSESSMENTS_DB)
    return Response(
        content=json_data, 
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=ICAO_ANNEX19_AUDIT_LOG.json"}
    )

@router.get(
    "/export/csv", 
    summary="Download de-identified hazard database logs as a flat CSV spreadsheet"
)
async def export_csv_audit_package():
    if not SAFETY_REPORTS_DB:
        raise HTTPException(status_code=404, detail="No operational records found to build export package.")
        
    csv_file = RegulatoryExportEngine.generate_csv_export(SAFETY_REPORTS_DB, RISK_ASSESSMENTS_DB)
    return StreamingResponse(
        iter([csv_file.getvalue()]), 
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=KCAA_FAA_SAFETY_EXPORT.csv"}
    )

# System Assembly Checklist: Ensure app.include_router(router) is executed in your main app module.
