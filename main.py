import os
import random
from fastapi import FastAPI, Depends, HTTPException, Header, File, UploadFile, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from PIL import Image
from dotenv import load_dotenv

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

import models
import security
from models import SessionLocal, engine

load_dotenv()

os.makedirs("uploads", exist_ok=True)

app = FastAPI(title="Veritas API", version="1.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise ValueError("Критическая ошибка: ADMIN_PASSWORD не установлен в .env")

MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'docx', 'xlsx', 'mp4', 'mp3', 'wav', 'm4a', 'pptx'}

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def save_file(file: UploadFile, prefix: str):
    if not file or not file.filename: 
        return None
        
    ext = file.filename.split('.')[-1].lower()
    
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Тип файла не поддерживается")
        
    file_bytes = await file.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Размер файла превышает 10 МБ")
    
    safe_name = f"{prefix}_{random.randint(10000, 99999)}.{ext}"
    path = f"uploads/{safe_name}"
    
    with open(path, "wb") as buffer:
        buffer.write(file_bytes)
    
    # Veritas remover
    if ext in ['jpg', 'jpeg', 'png']:
        try:
            with Image.open(path) as img:
                format_type = img.format
                clean_img = Image.new(img.mode, img.size)
                clean_img.paste(img) # Оптимизировано для экономии RAM
                clean_img.save(path, format=format_type)
        except Exception as e:
            print(f"[Scrubber Error] Ошибка изображения: {e}")
            
    elif ext == 'pdf':
        try:
            from pypdf import PdfReader, PdfWriter
            reader = PdfReader(path)
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            writer.add_metadata({}) 
            with open(path, "wb") as f:
                writer.write(f)
        except Exception as e:
            print(f"[Scrubber Error] Ошибка PDF: {e}")
            
    elif ext in ['docx', 'xlsx']:
        try:
            if ext == 'docx':
                from docx import Document
                doc = Document(path)
                props = doc.core_properties
            else:
                import openpyxl
                doc = openpyxl.load_workbook(path)
                props = doc.properties
                
            props.author = "" if ext == 'docx' else None
            if ext == 'docx': props.last_modified_by = ""
            else: props.lastModifiedBy = None
            props.title = ""
            props.subject = ""
            doc.save(path)
        except Exception as e:
            print(f"[Scrubber Error] Ошибка {ext.upper()}: {e}")
            
    elif ext == 'pptx':
        try:
            from pptx import Presentation
            prs = Presentation(path)
            props = prs.core_properties
            props.author = ""
            props.last_modified_by = ""
            props.title = ""
            props.subject = ""
            prs.save(path)
        except Exception as e:
            print(f"[Scrubber Error] Ошибка PPTX: {e}")
            
    elif ext in ['mp3', 'mp4', 'wav', 'm4a']:
        try:
            from mutagen import File as MutagenFile
            media_file = MutagenFile(path)
            if media_file is not None:
                media_file.delete()
                media_file.save()
        except Exception as e:
            print(f"[Scrubber Error] Ошибка медиафайла: {e}")

    return f"/{path}"

def get_ticket_messages(db, ticket_number):
    msgs = db.query(models.Message).filter(models.Message.ticket_number == ticket_number).order_by(models.Message.created_at).all()
    return [{"id": m.id, "sender": m.sender, "text": security.decrypt_text(m.encrypted_text), "file_url": m.file_url, "date": m.created_at} for m in msgs]

class TicketAccess(BaseModel): ticket_number: str; pin_code: str
class StatusUpdate(BaseModel): status: str

# /
@app.post("/api/tickets/create")
@limiter.limit("5/minute")
async def create_ticket(request: Request, category: str = Form(...), description: str = Form(...), file: UploadFile = File(None), db: Session = Depends(get_db)):
    ticket_num = f"UT-{random.randint(1000, 9999)}"
    pin_code = security.generate_pin()
    file_url = await save_file(file, ticket_num)
    
    # --- МАЯЧКИ ДЛЯ ЛОГОВ RENDER ---
    print(f"[DEBUG VERITAS] Сгенерирован PIN: {pin_code} (Длина: {len(pin_code)})")
    # -------------------------------
    
    new_ticket = models.Ticket(
        ticket_number=ticket_num, hashed_pin=security.get_password_hash(pin_code),
        category=category, encrypted_description=security.encrypt_text(description), file_url=file_url
    )
    db.add(new_ticket)
    db.commit()
    return {"ticket_number": ticket_num, "pin_code": pin_code}

@app.post("/api/tickets/check")
@limiter.limit("40/minute")
def check_ticket(request: Request, access: TicketAccess, db: Session = Depends(get_db)):
    clean_ticket_num = access.ticket_number.strip().upper().replace(" ", "")
    clean_pin = access.pin_code.strip().replace(" ", "")
    
    print(f"[DEBUG CHECK] Запрос верификации. Папка поиска: '{clean_ticket_num}', Очищенный PIN: '{clean_pin}'")
    
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == clean_ticket_num).first()
    if not ticket:
        print(f"[DEBUG CHECK] Тикет {clean_ticket_num} не обнаружен в SQLite!")
        raise HTTPException(status_code=401, detail="Неверные данные")
        
    if not security.verify_password(clean_pin, ticket.hashed_pin):
        print(f"[DEBUG CHECK] Хэши не совпали для тикета {clean_ticket_num}!")
        raise HTTPException(status_code=401, detail="Неверные данные")
        
    print(f"[DEBUG CHECK] Успешный вход в тикет {clean_ticket_num}")
    return {
        "ticket_number": ticket.ticket_number, "status": ticket.status, "category": ticket.category, 
        "description": security.decrypt_text(ticket.encrypted_description),
        "file_url": ticket.file_url, "messages": get_ticket_messages(db, ticket.ticket_number)
    }

@app.post("/api/tickets/message")
@limiter.limit("10/minute")
async def user_send_message(request: Request, ticket_number: str = Form(...), pin_code: str = Form(...), message: str = Form(""), file: UploadFile = File(None), db: Session = Depends(get_db)):
    clean_num = ticket_number.strip().upper().replace(" ", "")
    clean_pin = pin_code.strip().replace(" ", "")
    
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == clean_num).first()
    if not ticket or not security.verify_password(clean_pin, ticket.hashed_pin): 
        raise HTTPException(status_code=401, detail="Неверные данные")
        
    msg = models.Message(ticket_number=clean_num, sender="Заявитель", encrypted_text=security.encrypt_text(message), file_url=await save_file(file, "msg"))
    db.add(msg)
    db.commit()
    return {"message": "OK"}

@app.delete("/api/tickets/messages/{message_id}")
def user_delete_message(message_id: int, ticket_number: str = Header(...), pin_code: str = Header(...), db: Session = Depends(get_db)):
    clean_num = ticket_number.strip().upper().replace(" ", "")
    clean_pin = pin_code.strip().replace(" ", "")
    
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == clean_num).first()
    if not ticket or not security.verify_password(clean_pin, ticket.hashed_pin): 
        raise HTTPException(status_code=401, detail="Неверные данные")
        
    msg = db.query(models.Message).filter(models.Message.id == message_id, models.Message.sender == "Заявитель").first()
    if msg:
        db.delete(msg)
        db.commit()
    return {"message": "OK"}

# /admin
@app.get("/api/admin/tickets")
def get_all_tickets(db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    tickets = db.query(models.Ticket).order_by(models.Ticket.created_at.desc()).all()
    return [{
        "ticket_number": t.ticket_number, "category": t.category, "status": t.status,
        "description": security.decrypt_text(t.encrypted_description), "file_url": t.file_url,
        "messages": get_ticket_messages(db, t.ticket_number)
    } for t in tickets]

@app.patch("/api/admin/tickets/{ticket_number}/status")
def update_status(ticket_number: str, data: StatusUpdate, db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    ticket = db.query(models.Ticket).filter(models.Ticket.ticket_number == ticket_number).first()
    ticket.status = data.status
    db.commit()
    return {"message": "OK"}

@app.post("/api/admin/tickets/{ticket_number}/message")
async def admin_send_message(ticket_number: str, message: str = Form(""), file: UploadFile = File(None), db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    msg = models.Message(ticket_number=ticket_number, sender="Офицер", encrypted_text=security.encrypt_text(message), file_url=await save_file(file, "admin"))
    db.add(msg)
    db.commit()
    return {"message": "OK"}

@app.delete("/api/admin/messages/{message_id}")
def admin_delete_message(message_id: int, db: Session = Depends(get_db), admin_key: str = Header(None)):
    if admin_key != ADMIN_PASSWORD: raise HTTPException(status_code=403)
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if msg:
        db.delete(msg)
        db.commit()
    return {"message": "OK"}

@app.get("/")
def serve_index():
    return FileResponse("frontend/index.html")

@app.get("/admin")
def serve_admin():
    return FileResponse("frontend/admin.html")